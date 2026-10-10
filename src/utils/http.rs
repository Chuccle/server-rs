//! Response assembly for resident files and capability-opened streams.
//!
//! Both kinds of file answer through one evaluation of the request's
//! preconditions and range ([`evaluate`]), so a file answers the same status
//! whether it is held in memory or streamed off disk; only where the bytes come
//! from differs.
//!
//! Resident responses are pure: the headers were rendered when the file was
//! loaded and the body is a slice of an already-owned buffer, so answering a
//! request - including a ranged or conditional one - costs no syscalls and no
//! copies. A streamed file renders the same headers from the metadata of the
//! handle it streams, so its headers and bytes come from the same open file.

use crate::utils::cache::FileNode;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Bytes read from disk per chunk of a streamed body.
const STREAM_CHUNK: usize = 64 * 1024;

/// What a response says about the file it carries, rendered once.
pub struct Representation {
    pub len: u64,
    /// Truncated to whole seconds so it compares cleanly against an
    /// `If-Modified-Since`, which only has second granularity.
    pub modified: Option<std::time::SystemTime>,
    pub content_type: HeaderValue,
    pub last_modified: Option<HeaderValue>,
    pub etag: Option<HeaderValue>,
}

impl Representation {
    /// The headers for a file of `len` bytes at `path`, as its metadata
    /// describes it.
    ///
    /// The entity tag is a strong validator over the two things that change
    /// when the bytes do, spelled as tower-http's file service spelled it, so a
    /// file kept its tag across the change and a client can check a range
    /// against the size and time a listing gave it.
    /// `a_file_carries_one_entity_tag_resident_or_streamed` pins it, and the
    /// driver's `HttpParseFileVersion` parses it.
    pub fn of(path: &std::path::Path, metadata: &std::fs::Metadata, len: u64) -> Self {
        let modified = metadata.modified().ok().map(truncate_to_seconds);

        let content_type =
            HeaderValue::from_str(mime_guess::from_path(path).first_or_octet_stream().as_ref())
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));

        let last_modified = modified
            .map(httpdate::fmt_http_date)
            .and_then(|date| HeaderValue::from_str(&date).ok());

        let etag = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|since| {
                let (seconds, nanos) = (since.as_secs(), since.subsec_nanos());
                HeaderValue::from_str(&format!("\"{seconds:x}.{nanos:08x}-{len:x}\"")).ok()
            });

        Self {
            len,
            modified,
            content_type,
            last_modified,
            etag,
        }
    }
}

fn truncate_to_seconds(time: std::time::SystemTime) -> std::time::SystemTime {
    time.duration_since(std::time::UNIX_EPOCH)
        .map_or(time, |since| {
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(since.as_secs())
        })
}

/// What a request gets, decided from the file's validators and size alone.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    NotModified,
    PreconditionFailed,
    Unsatisfiable,
    Full,
    Partial(std::ops::RangeInclusive<u64>),
}

/// Preconditions in the order RFC 9110 section 13.2.2 evaluates them, then the
/// range.
///
/// `If-Match` compares strongly and `If-None-Match` weakly; a date is
/// consulted only when the tag header that outranks it is absent, and ignored
/// when it does not parse. A file with no tag fails any `If-Match` and passes
/// any `If-None-Match`; one with no time passes `If-Unmodified-Since` and
/// fails `If-Modified-Since`.
///
/// A `Range` that does not parse, cannot be satisfied, or asks for more than
/// one range is answered `416`: nothing sends a multipart range here, and
/// refusing one is cheaper than assembling `multipart/byteranges`.
fn evaluate(representation: &Representation, headers: &HeaderMap) -> Answer {
    let etag = representation.etag.as_ref().map(HeaderValue::as_bytes);

    if let Some(wanted) = header_bytes(headers, &header::IF_MATCH) {
        if !etag.is_some_and(|etag| wanted == b"*" || any_tag(wanted, |tag| tag == etag)) {
            return Answer::PreconditionFailed;
        }
    } else if let Some(since) = header_date(headers, &header::IF_UNMODIFIED_SINCE)
        && representation
            .modified
            .is_some_and(|modified| modified > since)
    {
        return Answer::PreconditionFailed;
    }

    if let Some(unwanted) = header_bytes(headers, &header::IF_NONE_MATCH) {
        if etag.is_some_and(|etag| {
            unwanted == b"*" || any_tag(unwanted, |tag| weak(tag) == weak(etag))
        }) {
            return Answer::NotModified;
        }
    } else if let Some(since) = header_date(headers, &header::IF_MODIFIED_SINCE)
        && representation
            .modified
            .is_some_and(|modified| modified <= since)
    {
        return Answer::NotModified;
    }

    let Some(raw) = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return Answer::Full;
    };

    let Ok(ranges) = http_range_header::parse_range_header(raw)
        .and_then(|parsed| parsed.validate(representation.len))
    else {
        return Answer::Unsatisfiable;
    };

    match ranges.as_slice() {
        [range] => Answer::Partial(range.clone()),
        _ => Answer::Unsatisfiable,
    }
}

/// A header's value, unless it is absent or empty.
fn header_bytes<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a [u8]> {
    headers
        .get(name)
        .map(HeaderValue::as_bytes)
        .filter(|value| !value.is_empty())
}

fn header_date(headers: &HeaderMap, name: &header::HeaderName) -> Option<std::time::SystemTime> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
}

/// Whether any entity tag in a comma-separated list satisfies `matches`.
/// Commas inside a quoted tag do not separate.
fn any_tag(list: &[u8], mut matches: impl FnMut(&[u8]) -> bool) -> bool {
    let mut quoted = false;
    let mut start = 0;

    for (index, byte) in list.iter().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                let tag = list.get(start..index).unwrap_or_default().trim_ascii();
                if !tag.is_empty() && matches(tag) {
                    return true;
                }
                start = index + 1;
            }
            _ => {}
        }
    }

    let tag = list.get(start..).unwrap_or_default().trim_ascii();
    !tag.is_empty() && matches(tag)
}

/// A tag without its weakness marker, for weak comparison.
fn weak(tag: &[u8]) -> &[u8] {
    tag.strip_prefix(b"W/").unwrap_or(tag)
}

/// Build the response for a file we are holding in memory.
pub fn resident_response(node: &FileNode, method: &Method, headers: &HeaderMap) -> Response {
    let representation = &node.representation;

    respond(
        representation,
        method,
        evaluate(representation, headers),
        |range| {
            // `validate` already proved the range sits inside the buffer; the clamp
            // just keeps the slice infallible without an unwrap.
            let from = usize::try_from(*range.start())
                .unwrap_or(usize::MAX)
                .min(node.data.len());
            let to = usize::try_from(range.end().saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(node.data.len());

            Body::from(node.data.slice(from..to.max(from)))
        },
    )
}

/// Build the response for a file streamed off the handle the router opened.
///
/// The headers come from that handle's metadata and the bytes from the handle
/// itself, so replacing the path after the open changes neither.
///
/// # Errors
///
/// The handle names a directory, or cannot be read or positioned.
pub async fn streamed_response(
    file: std::fs::File,
    path: &std::path::Path,
    method: &Method,
    headers: &HeaderMap,
) -> std::io::Result<Response> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return Err(std::io::ErrorKind::NotFound.into());
    }

    let representation = Representation::of(path, &metadata, metadata.len());
    let answer = evaluate(&representation, headers);

    let range = match &answer {
        Answer::Full if representation.len > 0 => Some(0..=representation.len - 1),
        Answer::Partial(range) => Some(range.clone()),
        _ => None,
    };

    let body = match range {
        Some(range) if *method != Method::HEAD => {
            let mut file = tokio::fs::File::from_std(file);
            file.seek(std::io::SeekFrom::Start(*range.start())).await?;
            let length = range.end() - range.start() + 1;
            Body::from_stream(tokio_util::io::ReaderStream::with_capacity(
                file.take(length),
                STREAM_CHUNK,
            ))
        }
        _ => Body::empty(),
    };

    Ok(respond(&representation, method, answer, |_| body))
}

/// The response for `answer`, taking the bytes of a range from `body` when
/// there are any to send.
fn respond(
    representation: &Representation,
    method: &Method,
    answer: Answer,
    body: impl FnOnce(std::ops::RangeInclusive<u64>) -> Body,
) -> Response {
    let total = representation.len;

    let response = match answer {
        Answer::NotModified => common(representation, StatusCode::NOT_MODIFIED).body(Body::empty()),
        Answer::PreconditionFailed => Response::builder()
            .status(StatusCode::PRECONDITION_FAILED)
            .body(Body::empty()),
        Answer::Unsatisfiable => Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{total}"))
            .body(Body::empty()),
        Answer::Full => common(representation, StatusCode::OK)
            .header(header::CONTENT_LENGTH, total)
            .body(if *method == Method::HEAD || total == 0 {
                Body::empty()
            } else {
                body(0..=total - 1)
            }),
        Answer::Partial(range) => {
            let (first, last) = (*range.start(), *range.end());

            common(representation, StatusCode::PARTIAL_CONTENT)
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {first}-{last}/{total}"),
                )
                .header(header::CONTENT_LENGTH, last - first + 1)
                .body(if *method == Method::HEAD {
                    Body::empty()
                } else {
                    body(range)
                })
        }
    };

    response.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Headers every response that describes this file carries.
fn common(representation: &Representation, status: StatusCode) -> axum::http::response::Builder {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, representation.content_type.clone())
        .header(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    if let Some(value) = &representation.last_modified {
        builder = builder.header(header::LAST_MODIFIED, value.clone());
    }

    if let Some(value) = &representation.etag {
        builder = builder.header(header::ETAG, value.clone());
    }

    builder
}
