//! Response assembly for resident files and capability-opened streams.
//!
//! Resident responses are pure: the headers were rendered when the file was loaded
//! and the body is a slice of an already-owned buffer, so answering a request -
//! including a ranged or conditional one - costs no syscalls and no copies.
//!
//! Range parsing goes through the same crate `tower_http`'s `ServeFile` uses,
//! so resident and streamed files agree on what a `Range` header means.

use crate::utils::cache::FileNode;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Keep tower-http's conditional requests, ranges, MIME type and HEAD
/// behaviour while supplying the already confined file rather than a name
/// it could reopen. Metadata and bytes come from this same open handle.
pub(crate) async fn streamed_response(
    file: std::fs::File,
    path: &std::path::Path,
    mut request: axum::http::Request<Body>,
) -> std::io::Result<Response> {
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    let name = path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let encoded = percent_encoding::utf8_percent_encode(&name, percent_encoding::NON_ALPHANUMERIC);
    *request.uri_mut() = format!("/{encoded}")
        .parse()
        .map_err(std::io::Error::other)?;
    let backend = OpenedBackend {
        file: std::sync::Arc::new(file),
        metadata,
    };
    Ok(tower_http::services::ServeDir::with_backend("", backend)
        .append_index_html_on_directories(false)
        .try_call(request)
        .await?
        .into_response())
}

/// A private single-file backend. The router has already selected and opened
/// the file; service paths are used only to infer its MIME type.
#[derive(Clone)]
struct OpenedBackend {
    file: std::sync::Arc<std::fs::File>,
    metadata: std::fs::Metadata,
}

impl tower_http::services::fs::Backend for OpenedBackend {
    type File = OpenedFile;
    type Metadata = std::fs::Metadata;
    type OpenFuture = std::future::Ready<std::io::Result<OpenedFile>>;
    type MetadataFuture = std::future::Ready<std::io::Result<std::fs::Metadata>>;

    fn open(&self, _: std::path::PathBuf) -> Self::OpenFuture {
        std::future::ready(self.file.try_clone().map(|file| OpenedFile {
            file: tokio::fs::File::from_std(file),
            metadata: self.metadata.clone(),
        }))
    }

    fn metadata(&self, _: std::path::PathBuf) -> Self::MetadataFuture {
        std::future::ready(Ok(self.metadata.clone()))
    }
}

struct OpenedFile {
    file: tokio::fs::File,
    metadata: std::fs::Metadata,
}

impl tokio::io::AsyncRead for OpenedFile {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.file).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncSeek for OpenedFile {
    fn start_seek(
        mut self: std::pin::Pin<&mut Self>,
        position: std::io::SeekFrom,
    ) -> std::io::Result<()> {
        std::pin::Pin::new(&mut self.file).start_seek(position)
    }

    fn poll_complete(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        std::pin::Pin::new(&mut self.file).poll_complete(context)
    }
}

impl tower_http::services::fs::File for OpenedFile {
    type Metadata = std::fs::Metadata;
    type MetadataFuture<'a> = std::future::Ready<std::io::Result<std::fs::Metadata>>;

    fn metadata(&self) -> Self::MetadataFuture<'_> {
        std::future::ready(Ok(self.metadata.clone()))
    }
}

/// Build the response for a file we are holding in memory.
///
/// Anything not understood degrades to a full `200` rather than an error,
/// which is what the RFC asks for with an unparseable `Range`.
pub fn resident_response(node: &FileNode, method: &Method, headers: &HeaderMap) -> Response {
    if is_not_modified(node, headers) {
        return common(node, StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .unwrap_or_else(|_| internal());
    }

    let requested = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| single_range(raw, node.len));

    match requested {
        Some(Ok(range)) => partial(node, method, range),
        Some(Err(())) => unsatisfiable(node),
        None => full(node, method),
    }
}

/// `None` - no range, or one we are entitled to ignore.
/// `Some(Err(()))` - a well-formed range that cannot be satisfied.
/// `Some(Ok(range))` - an inclusive byte range to serve.
fn single_range(raw: &str, len: u64) -> Option<Result<std::ops::RangeInclusive<u64>, ()>> {
    let parsed = http_range_header::parse_range_header(raw).ok()?;

    let Ok(ranges) = parsed.validate(len) else {
        return Some(Err(()));
    };

    // Multipart ranges are legal to ignore, and serving the whole body beats
    // assembling a multipart/byteranges payload for a case nothing sends.
    let mut ranges = ranges.into_iter();
    let first = ranges.next()?;

    if ranges.next().is_some() {
        None
    } else {
        Some(Ok(first))
    }
}

/// Headers every successful response to this file carries.
fn common(node: &FileNode, status: StatusCode) -> axum::http::response::Builder {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, node.content_type.clone())
        .header(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    if let Some(value) = &node.last_modified {
        builder = builder.header(header::LAST_MODIFIED, value.clone());
    }

    if let Some(value) = &node.etag {
        builder = builder.header(header::ETAG, value.clone());
    }

    builder
}

fn full(node: &FileNode, method: &Method) -> Response {
    common(node, StatusCode::OK)
        .header(header::CONTENT_LENGTH, node.len)
        .body(body_for(method, node.data.clone()))
        .unwrap_or_else(|_| internal())
}

fn partial(node: &FileNode, method: &Method, range: std::ops::RangeInclusive<u64>) -> Response {
    let (first, last) = (*range.start(), *range.end());
    let total = node.len;

    // `validate` already proved the range sits inside the buffer; the clamp
    // below just keeps the slice infallible without an unwrap.
    let from = usize::try_from(first).unwrap_or(usize::MAX).min(node.data.len());
    let to = usize::try_from(last.saturating_add(1))
        .unwrap_or(usize::MAX)
        .min(node.data.len());

    let slice = node.data.slice(from..to.max(from));

    common(node, StatusCode::PARTIAL_CONTENT)
        .header(
            header::CONTENT_RANGE,
            format!("bytes {first}-{last}/{total}"),
        )
        .header(header::CONTENT_LENGTH, last - first + 1)
        .body(body_for(method, slice))
        .unwrap_or_else(|_| internal())
}

fn unsatisfiable(node: &FileNode) -> Response {
    let total = node.len;

    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{total}"))
        .body(Body::empty())
        .unwrap_or_else(|_| internal())
}

/// A `HEAD` reply carries the headers of the `GET` it stands in for, but no
/// body. This layer is exercised directly by tests and by `Router::call`, so it
/// cannot rely on the connection layer stripping the body for it.
fn body_for(method: &Method, data: bytes::Bytes) -> Body {
    if *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(data)
    }
}

fn is_not_modified(node: &FileNode, headers: &HeaderMap) -> bool {
    // An entity tag is the stronger validator, so it wins outright when the
    // client offers one - matched or not.
    if let Some(requested) = headers.get(header::IF_NONE_MATCH) {
        return requested.as_bytes() == b"*"
            || node
                .etag
                .as_ref()
                .is_some_and(|tag| requested.as_bytes() == tag.as_bytes());
    }

    if let Some(modified) = node.modified
        && let Some(since) = headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok())
    {
        // Both sides are second-granularity, so "not newer" means unchanged.
        return modified <= since;
    }

    false
}

fn internal() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
