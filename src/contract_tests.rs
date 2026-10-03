//! Checks this server against the wire contract it shares with the `BlorgFS`
//! driver (`schemas/contract.json`).
//!
//! The router tests elsewhere drive handlers through `tower::Service`, which
//! skips the connection layer - and the connection layer is where most of what
//! the driver depends on lives: Content-Length framing, keep-alive, and the
//! exact request bytes it sends. So everything here goes over a real socket
//! with the driver's own request bytes from the contract.
//!
//! Each test names the behaviour it covers with a `contract: Bnn` tag;
//! `schemas/tools/check_traceability.py` fails CI if a behaviour this server is
//! responsible for has none.

use crate::contract::{self, route, status};
use crate::generated::blorg_meta_flat::{Directory, DirectoryEntryMetadata};
use crate::utils::meta::RawMeta;
use crate::{AppState, build_router, utils};
use std::fmt::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Above the default `max_resident_file_bytes`, so it is streamed off disk.
const LARGE: usize = 9 * 1024 * 1024;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// What the driver requires of every response before it reads a byte of
    /// body: exactly one Content-Length, and no transfer coding.
    fn assert_framed(&self, what: &str) {
        let lengths = self.header_values("content-length");
        assert_eq!(
            lengths.len(),
            1,
            "{what}: want one Content-Length, got {lengths:?}"
        );
        assert!(
            self.header_values("transfer-encoding").is_empty(),
            "{what}: the driver has no chunked decoder"
        );
        assert_eq!(
            lengths[0].parse::<usize>().unwrap(),
            self.body.len(),
            "{what}: Content-Length disagrees with the body"
        );
    }
}

/// The tree the requests in the contract point at, plus files for the range
/// and error cases.
struct Server {
    _root: tempfile::TempDir,
    addr: std::net::SocketAddr,
}

impl Server {
    async fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path();

        std::fs::create_dir_all(base.join("media")).unwrap();
        std::fs::write(base.join("media/file.bin"), pattern(1000)).unwrap();
        std::fs::write(base.join("media/large.bin"), pattern(LARGE)).unwrap();
        std::fs::create_dir_all(base.join("a b")).unwrap();
        std::fs::write(base.join("a b/\u{e9}t\u{e9}.bin"), b"accent").unwrap();

        let state = Arc::new(AppState::new(base, utils::cache::Config::default()).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, build_router(state)).await });

        Self { _root: root, addr }
    }

    async fn connect(&self) -> tokio::net::TcpStream {
        tokio::net::TcpStream::connect(self.addr).await.unwrap()
    }

    /// One request on a fresh connection.
    async fn send(&self, wire: &[u8]) -> Response {
        let mut stream = self.connect().await;
        exchange(&mut stream, wire).await
    }
}

/// The request bytes the driver sends, built the way `Client.c` builds them.
/// The contract's own `REQUESTS` pin that format; this just lets tests vary
/// the path and range.
fn driver_request(route: &str, path: &str, range: Option<(u64, u64)>) -> Vec<u8> {
    let encoded: String = path
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let mut wire = format!(
        "GET {route}?{}={encoded} HTTP/1.1\r\nHost: contract.test\r\nConnection: keep-alive\r\n",
        contract::QUERY_PATH
    );
    if let Some((first, last)) = range {
        write!(wire, "Range: bytes={first}-{last}\r\n").unwrap();
    }
    wire.push_str("\r\n");
    wire.into_bytes()
}

/// Write one request and read exactly one Content-Length framed response,
/// leaving the stream positioned for the next one - which is how the driver
/// reuses a pooled connection.
async fn exchange(stream: &mut tokio::net::TcpStream, wire: &[u8]) -> Response {
    stream.write_all(wire).await.unwrap();

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = stream
            .read_u8()
            .await
            .expect("connection closed mid-headers");
        head.push(byte);
    }

    let text = String::from_utf8(head).unwrap();
    let mut lines = text.split("\r\n").filter(|line| !line.is_empty());
    let status = lines.next().unwrap()[9..12].parse().unwrap();
    let headers: Vec<(String, String)> = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.trim().to_owned(), value.trim().to_owned())
        })
        .collect();

    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| value.parse::<usize>().unwrap());
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();

    Response {
        status,
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------
// The contract itself
// ---------------------------------------------------------------------------

#[test]
fn contract_lists_every_route_this_server_serves() {
    // `build_router` takes its paths from `contract::route`; this is the other
    // direction - nothing the contract promises is missing from the server.
    let served = [
        route::DIR_INFO,
        route::DIR_ENTRY_INFO,
        route::FILE,
        route::HEALTHCHECK,
    ];
    for wire in contract::REQUESTS {
        assert!(
            served.contains(&wire.route),
            "{} targets an unserved route",
            wire.id
        );
    }
}

// contract: B04
#[test]
fn error_statuses_are_the_contracts() {
    use crate::error::AppError;
    use axum::response::IntoResponse as _;

    for (error, want) in [
        (AppError::BadRequest, status::BAD_REQUEST),
        (AppError::PathTraversal, status::FORBIDDEN),
        (AppError::PermissionDenied, status::FORBIDDEN),
        (AppError::NotFound, status::NOT_FOUND),
        (AppError::Internal, status::INTERNAL),
    ] {
        assert_eq!(error.into_response().status().as_u16(), want, "{error:?}");
    }
}

// ---------------------------------------------------------------------------
// Metadata encoding
// ---------------------------------------------------------------------------

// contract: B07
#[test]
fn reference_fixtures_decode_to_their_declared_values() {
    for fixture in contract::LISTINGS {
        let directory = flatbuffers::root::<Directory>(fixture.bytes).unwrap();
        assert_listing_matches(fixture, directory);
    }

    for fixture in contract::ENTRIES {
        let entry = flatbuffers::root::<DirectoryEntryMetadata>(fixture.bytes).unwrap();
        assert_entry_matches(fixture, entry);
    }
}

// contract: B06 B07
#[test]
fn this_servers_encoder_writes_what_the_fixtures_declare() {
    for fixture in contract::LISTINGS {
        // `flat::listing` takes one name-sorted list of children; the contract
        // keeps files and subdirectories apart, each in byte-wise order.
        let mut children: Vec<(Box<str>, RawMeta)> = fixture
            .files
            .iter()
            .map(|file| {
                (
                    file.name.into(),
                    RawMeta {
                        size: file.size,
                        created: file.created,
                        modified: file.modified,
                        accessed: file.accessed,
                        is_dir: false,
                    },
                )
            })
            .chain(fixture.subdirectories.iter().map(|subdirectory| {
                (
                    subdirectory.name.into(),
                    RawMeta {
                        size: 0,
                        created: subdirectory.created,
                        modified: subdirectory.modified,
                        accessed: subdirectory.accessed,
                        is_dir: true,
                    },
                )
            }))
            .collect();
        children.sort_by(|a, b| a.0.cmp(&b.0));

        let encoded = utils::flat::listing(&children);
        let directory = flatbuffers::root::<Directory>(&encoded).unwrap();
        assert_listing_matches(fixture, directory);
    }

    for fixture in contract::ENTRIES {
        let encoded = utils::flat::entry(&RawMeta {
            size: fixture.size,
            created: fixture.created,
            modified: fixture.modified,
            accessed: fixture.accessed,
            is_dir: fixture.directory,
        });
        let entry = flatbuffers::root::<DirectoryEntryMetadata>(&encoded).unwrap();
        assert_entry_matches(fixture, entry);
    }
}

fn assert_listing_matches(fixture: &contract::Listing, directory: Directory<'_>) {
    let id = fixture.id;

    // contract: B06 -- both vectors present, even when empty.
    let files = directory
        .files()
        .unwrap_or_else(|| panic!("{id}: no files vector"));
    let subdirectories = directory
        .subdirectories()
        .unwrap_or_else(|| panic!("{id}: no subdirectories vector"));

    assert_eq!(files.len(), fixture.files.len(), "{id}: file count");
    for (got, want) in files.iter().zip(fixture.files) {
        assert_eq!(got.name(), Some(want.name), "{id}");
        assert_eq!(got.size(), want.size, "{id}: {} size", want.name);
        assert_eq!(got.created(), want.created, "{id}: {} created", want.name);
        assert_eq!(
            got.modified(),
            want.modified,
            "{id}: {} modified",
            want.name
        );
        assert_eq!(
            got.accessed(),
            want.accessed,
            "{id}: {} accessed",
            want.name
        );
    }

    assert_eq!(
        subdirectories.len(),
        fixture.subdirectories.len(),
        "{id}: subdirectory count"
    );
    for (got, want) in subdirectories.iter().zip(fixture.subdirectories) {
        assert_eq!(got.name(), Some(want.name), "{id}");
        assert_eq!(got.created(), want.created, "{id}: {} created", want.name);
        assert_eq!(
            got.modified(),
            want.modified,
            "{id}: {} modified",
            want.name
        );
        assert_eq!(
            got.accessed(),
            want.accessed,
            "{id}: {} accessed",
            want.name
        );
    }
}

fn assert_entry_matches(fixture: &contract::Entry, entry: DirectoryEntryMetadata<'_>) {
    let id = fixture.id;
    assert_eq!(entry.size(), fixture.size, "{id}: size");
    assert_eq!(entry.created(), fixture.created, "{id}: created");
    assert_eq!(entry.modified(), fixture.modified, "{id}: modified");
    assert_eq!(entry.accessed(), fixture.accessed, "{id}: accessed");
    assert_eq!(entry.directory(), fixture.directory, "{id}: directory");
}

// contract: B10
#[test]
fn timestamps_are_filetime_and_never_zero() {
    use crate::utils::windows::time::WINDOWS_EPOCH_OFFSET;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("f");
    std::fs::write(&path, b"x").unwrap();

    let meta = RawMeta::from_std(&std::fs::metadata(&path).unwrap());
    // Anything after 1970 is above the 1601->1970 offset; a Unix-epoch value
    // or a 0 left by a platform that cannot report `created` would not be.
    for (name, value) in [
        ("created", meta.created),
        ("modified", meta.modified),
        ("accessed", meta.accessed),
    ] {
        assert!(
            value > WINDOWS_EPOCH_OFFSET,
            "{name} = {value} is not a post-1970 FILETIME"
        );
    }
}

// ---------------------------------------------------------------------------
// Over the wire, with the driver's request bytes
// ---------------------------------------------------------------------------

// contract: B02 B05
#[tokio::test]
async fn the_drivers_exact_requests_succeed() {
    let server = Server::start().await;

    for request in contract::REQUESTS {
        let response = server.send(request.wire).await;
        let want = match request.route {
            route::FILE => status::FILE_OK,
            route::DIR_INFO => status::DIR_INFO_OK,
            route::DIR_ENTRY_INFO => status::DIR_ENTRY_INFO_OK,
            other => panic!("{}: no expectation for {other}", request.id),
        };
        assert_eq!(response.status, want, "{}", request.id);
        response.assert_framed(request.id);

        if let Some((first, last)) = request.range {
            let first = usize::try_from(first).unwrap();
            let last = usize::try_from(last).unwrap();
            assert_eq!(response.body, pattern(1000)[first..=last], "{}", request.id);
        }
    }
}

// contract: B01 B02
#[tokio::test]
async fn ranges_are_exact_resident_or_streamed() {
    let server = Server::start().await;
    let large = u64::try_from(LARGE).unwrap();

    for (path, first, last) in [
        ("\\media\\file.bin", 0, 999),
        ("\\media\\file.bin", 999, 999),
        ("\\media\\large.bin", 0, 0),
        ("\\media\\large.bin", 8_388_600, 8_388_700),
        ("\\media\\large.bin", large - 1, large - 1),
    ] {
        let what = format!("{path} {first}-{last}");
        let response = server
            .send(&driver_request(route::FILE, path, Some((first, last))))
            .await;

        assert_eq!(response.status, status::FILE_OK, "{what}");
        response.assert_framed(&what);
        assert_eq!(
            u64::try_from(response.body.len()).unwrap(),
            last - first + 1,
            "{what}"
        );
        let expected: Vec<u8> = (first..=last)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        assert!(response.body == expected, "{what}: wrong bytes");
    }
}

// contract: B03
#[tokio::test]
async fn one_connection_carries_many_requests() {
    let server = Server::start().await;
    let mut stream = server.connect().await;

    // Mixed on purpose: a streamed body followed by a resident one followed by
    // an error is exactly where a framing mistake would desync the stream.
    let sequence = [
        (
            driver_request(route::FILE, "\\media\\large.bin", Some((0, 65_535))),
            status::FILE_OK,
        ),
        (
            driver_request(route::DIR_INFO, "\\", None),
            status::DIR_INFO_OK,
        ),
        (
            driver_request(route::DIR_ENTRY_INFO, "\\missing", None),
            status::NOT_FOUND,
        ),
        (
            driver_request(route::FILE, "\\media\\file.bin", Some((10, 19))),
            status::FILE_OK,
        ),
    ];

    for (index, (wire, want)) in sequence.iter().enumerate() {
        let response = exchange(&mut stream, wire).await;
        assert_eq!(
            response.status, *want,
            "request {index} on the shared connection"
        );
        assert!(
            !response
                .header_values("connection")
                .iter()
                .any(|value| value.eq_ignore_ascii_case("close")),
            "request {index}: server asked to close a keep-alive connection"
        );
    }
}

// contract: B04 B02
#[tokio::test]
async fn failures_are_bare_status_codes() {
    let server = Server::start().await;

    let cases = [
        (
            "missing file",
            driver_request(route::DIR_ENTRY_INFO, "\\media\\nope.bin", None),
            status::NOT_FOUND,
        ),
        (
            "file as directory",
            driver_request(route::DIR_INFO, "\\media\\file.bin\\x", None),
            status::NOT_FOUND,
        ),
        (
            "escape the root",
            driver_request(route::DIR_INFO, "\\..\\..", None),
            status::FORBIDDEN,
        ),
        (
            "no path parameter",
            format!(
                "GET {} HTTP/1.1\r\nHost: contract.test\r\n\r\n",
                route::DIR_INFO
            )
            .into_bytes(),
            status::BAD_REQUEST,
        ),
        (
            "resident range at EOF",
            driver_request(route::FILE, "\\media\\file.bin", Some((1000, 1003))),
            status::RANGE_NOT_SATISFIABLE,
        ),
        (
            "streamed range at EOF",
            driver_request(
                route::FILE,
                "\\media\\large.bin",
                Some((9 * 1024 * 1024, 9 * 1024 * 1024 + 3)),
            ),
            status::RANGE_NOT_SATISFIABLE,
        ),
    ];

    for (what, wire, want) in cases {
        let response = server.send(&wire).await;
        assert_eq!(response.status, want, "{what}");
        response.assert_framed(what);
    }
}

// contract: B05
#[tokio::test]
async fn every_path_form_the_driver_sends_resolves() {
    let server = Server::start().await;

    for path in [
        "\\",
        "",
        "/",
        "\\media",
        "/media",
        "\\media\\",
        "\\a b\\..\\media",
    ] {
        let response = server
            .send(&driver_request(route::DIR_INFO, path, None))
            .await;
        assert_eq!(response.status, status::DIR_INFO_OK, "{path:?}");
    }
}

// contract: B06 B08
#[tokio::test]
async fn listing_and_entry_agree_with_content() {
    let server = Server::start().await;

    let response = server
        .send(&driver_request(route::DIR_INFO, "\\media", None))
        .await;
    let listing = flatbuffers::root::<Directory>(&response.body).unwrap();
    let files = listing.files().unwrap();
    let names: Vec<&str> = files.iter().map(|file| file.name().unwrap()).collect();
    assert_eq!(names, ["file.bin", "large.bin"], "byte-wise name order");
    assert_eq!(listing.subdirectories().map(|v| v.len()), Some(0));

    for file in files {
        let path = format!("\\media\\{}", file.name().unwrap());
        let entry = server
            .send(&driver_request(route::DIR_ENTRY_INFO, &path, None))
            .await;
        let entry = flatbuffers::root::<DirectoryEntryMetadata>(&entry.body).unwrap();
        assert_eq!(
            entry.size(),
            file.size(),
            "{path}: listing and entry disagree"
        );
        assert!(!entry.directory(), "{path}");

        let last = file.size() - 1;
        let content = server
            .send(&driver_request(route::FILE, &path, Some((last, last))))
            .await;
        assert_eq!(
            content.status,
            status::FILE_OK,
            "{path}: last reported byte is not servable"
        );
    }
}
