// Lint levels live in Cargo.toml's `[lints]` table, which - unlike an
// attribute here - covers every target in the package uniformly. This
// module-scoped allow is the exception: it is the only mechanism for
// excluding just the generated code while everything else stays covered.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::restriction,
    clippy::nursery,
    unused_imports,
    mismatched_lifetime_syntaxes
)]
mod generated {
    include!(concat!(
        env!("OUT_DIR"),
        "/metadata_flatbuffer_generated.rs"
    ));
}
pub mod error;
pub mod utils;

use error::AppError;

/// Extracts the required `path` query parameter from `uri`'s query string.
///
/// This bypasses `axum::extract::Query`'s `serde`-deserialise pipeline - a
/// derive-generated visitor, field-name matching, and an unconditional
/// `String` allocation for the value, none of which a single required field
/// needs. Borrows from `uri` whenever the value has no percent-escapes, which
/// is the common case.
///
/// # Errors
///
/// [`AppError::BadRequest`] if the query has no `path` key or its value is not
/// valid UTF-8 once decoded - the same case `axum::extract::Query` rejects a
/// missing required field for, just without a `serde` dependency to get there.
pub fn extract_path(uri: &axum::http::Uri) -> Result<std::borrow::Cow<'_, str>, AppError> {
    let query = uri.query().unwrap_or("");

    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("path=") {
            return percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .map_err(|_| AppError::BadRequest);
        }
    }

    Err(AppError::BadRequest)
}

/// Reads one unsigned integer query parameter, or `None` if `name` is absent
/// or its value is not a decimal `u64`.
fn query_u64(uri: &axum::http::Uri, name: &str) -> Option<u64> {
    uri.query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))?
        .parse()
        .ok()
}

/// A metadata answer, marked `no-store` when the change feed cannot vouch for
/// it (see [`utils::cache::Freshness`]).
fn answer(body: bytes::Bytes, freshness: utils::cache::Freshness) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let mut response = body.into_response();
    mark(&mut response, freshness);
    response
}

fn mark(response: &mut axum::response::Response, freshness: utils::cache::Freshness) {
    if freshness == utils::cache::Freshness::Unvouched {
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
    }
}

/// Handlers own nothing but the cache tier and the counters; everything a
/// request needs is reachable through [`utils::cache::Store`].
pub struct AppState {
    pub store: utils::cache::Store,
    pub cache_stats: utils::stats::Cache,
}

impl AppState {
    /// # Errors
    ///
    /// Propagates the I/O error if `base_path` cannot be canonicalised.
    pub fn new(base_path: &std::path::Path, config: utils::cache::Config) -> std::io::Result<Self> {
        Ok(Self {
            store: utils::cache::Store::new(base_path, config)?,
            cache_stats: utils::stats::Cache::new(),
        })
    }
}

/// `GET /get_dir_entry_info` - metadata for one entry.
///
/// # Errors
///
/// Traversal, missing path, or permission denied.
pub async fn get_dir_entry_info_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    uri: axum::http::Uri,
) -> Result<axum::response::Response, AppError> {
    let path = extract_path(&uri)?;
    log_debug!("[FILE INFO] Handling request for: {path}");

    let (encoded, origin, freshness) = data.store.entry_metadata(&path).await?;
    data.cache_stats.record(origin);

    Ok(answer(encoded, freshness))
}

/// Most entries one `get_dir_info?subtree=` answer will carry, whatever the
/// client asks for: it bounds the scanning a single request can cause.
const SUBTREE_MAX_ENTRIES: usize = 65_536;

/// The `subtree` budget a request asks for, capped at [`SUBTREE_MAX_ENTRIES`];
/// `0`, a plain listing, when it asks for none.
fn subtree_budget(uri: &axum::http::Uri) -> usize {
    query_u64(uri, "subtree").map_or(0, |budget| {
        usize::try_from(budget)
            .unwrap_or(usize::MAX)
            .min(SUBTREE_MAX_ENTRIES)
    })
}

/// `GET /get_dir_info` - the serialised listing for a directory.
///
/// With `subtree=N`, the listings beneath it too, up to `N` entries in all
/// (see [`utils::cache::Store::directory_subtree`]).
///
/// # Errors
///
/// Traversal, missing path, or an unreadable directory.
pub async fn get_dir_info_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    uri: axum::http::Uri,
) -> Result<axum::response::Response, AppError> {
    let path = extract_path(&uri)?;
    log_debug!("[DIR INFO] Handling request for: {path}");

    let budget = subtree_budget(&uri);

    let (encoded, origin, freshness) = if budget == 0 {
        data.store.directory_listing(&path).await?
    } else {
        data.store.directory_subtree(&path, budget).await?
    };
    data.cache_stats.record(origin);

    Ok(answer(encoded, freshness))
}

/// `GET /get_changes?epoch=E&since=G` - what changed after generation `G`.
///
/// Held until something has when nothing has yet. See [`utils::feed`] for the
/// contract. A client with no epoch yet sends none (or `0`) and is answered
/// with a reset carrying the current generation.
///
/// # Errors
///
/// [`AppError::FeedUnavailable`] while the watcher is not running, which tells
/// a client to fall back to expiring what it caches.
pub async fn get_changes_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    uri: axum::http::Uri,
) -> Result<axum::response::Response, AppError> {
    let epoch = query_u64(&uri, "epoch").unwrap_or(0);
    let since = query_u64(&uri, "since").unwrap_or(0);
    let feed = data.store.feed();

    let batch = feed
        .poll(epoch, since)
        .await
        .ok_or(AppError::FeedUnavailable)?;

    Ok(answer(
        batch.encode(feed.epoch()),
        utils::cache::Freshness::Unvouched,
    ))
}

/// `GET`/`HEAD /get_file` - file contents, from memory when resident.
///
/// # Errors
///
/// Traversal, missing path, or permission denied.
pub async fn get_file_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<axum::response::Response, AppError> {
    // Already own the whole request for `ServeFile` below, so there is no
    // separate `Uri` extractor to clone here - just read the one already in
    // hand.
    let path = extract_path(request.uri())?.into_owned();
    log_debug!("[FILE READ] Handling request for: {path}");

    let (canonical, content, origin, freshness) = data.store.file_content(&path).await?;
    data.cache_stats.record(origin);

    let mut response = match content {
        // Answered entirely from memory: no open, no read, no page-cache round
        // trip, and the body is a slice of a buffer we already hold.
        utils::cache::Content::Resident(node) => {
            utils::http::resident_response(&node, request.method(), request.headers())
        }

        // Open beneath the export root and stream that same handle. Reopening
        // a cached canonical pathname here would reintroduce traversal races.
        utils::cache::Content::Streamed => {
            let file = data.store.open_file(&canonical).await?;
            utils::http::streamed_response(file, &canonical, request).await?
        }
    };

    mark(&mut response, freshness);

    Ok(response)
}

/// Every route the server serves, in one place, so that tests and benchmarks
/// exercise the same wiring as production.
pub fn build_router(state: std::sync::Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route(
            "/get_dir_entry_info",
            axum::routing::get(get_dir_entry_info_handler),
        )
        .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
        .route("/get_changes", axum::routing::get(get_changes_handler))
        .route("/get_file", axum::routing::get(get_file_handler))
        .route("/get_file", axum::routing::head(get_file_handler))
        .route(
            "/healthcheck",
            axum::routing::get(|| async { axum::http::StatusCode::OK }),
        )
        .with_state(state)
}

/// Parse the command line, build the server and serve until shutdown.
///
/// # Errors
///
/// Propagates socket bind and serve failures, and any I/O error from
/// canonicalising the served root.
pub async fn run() -> std::io::Result<()> {
    use axum::serve::ListenerExt as _;

    #[cfg(feature = "logging")]
    utils::logging::init();

    let path_argument = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!(
            "Usage: {} <directory-path>",
            std::env::args()
                .next()
                .unwrap_or_else(|| "server-rs".to_owned())
        );
        std::process::exit(1);
    });

    let path = resolve_base_path(&path_argument);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let state = std::sync::Arc::new(AppState::new(&path, utils::cache::Config::default())?);

    #[cfg(feature = "stats")]
    start_cache_statistics_logger(state.clone());

    start_fs_watcher(state.store.base().to_path_buf(), state.clone());

    let app = build_router(state);

    log_info!("Starting server on port {} serving path: {:?}", port, &path);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await?
        // Off by default in axum/tokio. Without it, any response written in
        // more than one TCP segment - which every streamed `ServeFile` body
        // is - stalls on Nagle's algorithm interacting with the peer's
        // delayed-ACK timer: ~40ms of dead time on every such request under
        // keep-alive, regardless of how fast the handler itself runs.
        .tap_io(|stream| {
            if let Err(e) = stream.set_nodelay(true) {
                log_warn_with_context!(e, "Failed to set TCP_NODELAY on accepted connection");
            }
        });
    axum::serve(listener, app).await?;

    Ok(())
}

/// Validate the served root before anything else runs against it.
///
/// The root is canonicalised again inside [`utils::cache::Store::new`]; this
/// pass exists to fail loudly, with a useful message, rather than as a bare
/// I/O error out of `main`.
pub fn resolve_base_path(argument: &str) -> std::path::PathBuf {
    let base_path = std::path::Path::new(argument);

    if !base_path.is_dir() {
        log_error!("Provided path '{argument}' is not an existing directory");
        std::process::exit(1);
    }

    match std::fs::symlink_metadata(base_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            log_error!("Provided path '{argument}' is a symlink");
            std::process::exit(1);
        }
        Ok(_) => {}
        Err(e) => {
            log_error_with_context!(e, "Error accessing metadata for '{}'", argument);
            std::process::exit(1);
        }
    }

    match base_path.canonicalize() {
        Ok(canonical) => canonical,
        Err(e) => {
            log_error_with_context!(e, "Failed to canonicalize path '{}'", argument);
            std::process::exit(1);
        }
    }
}

/// Watches `path` recursively, feeding file-system events to the cache and the
/// change feed.
///
/// `path` must be the canonical root: `notify` builds event paths by joining
/// the watched root with the on-disk name, so watching the canonical form is
/// what makes event paths line up with the cache keys they invalidate.
///
/// The feed goes live only once the watch is in place, and stops for good on
/// the first error the watcher reports: an error means events may have been
/// lost (a directory it could not add a watch for, say), and a feed that might
/// be missing changes must not tell clients there were none.
///
/// On Windows it never goes live. When `ReadDirectoryChangesW` overflows its
/// buffer, `notify` stops watching without reporting an error or a rescan, so
/// the feed would go on vouching for a tree nobody is watching.
pub fn start_fs_watcher(path: std::path::PathBuf, state: std::sync::Arc<AppState>) {
    tokio::spawn(async move {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);

        let watching = notify_debouncer_full::new_debouncer(
            tokio::time::Duration::from_secs(2),
            None,
            move |res| {
                if let Err(e) = tx.blocking_send(res) {
                    log_error_with_context!(e, "watch send error");
                }
            },
        )
        .and_then(|mut debouncer| {
            debouncer
                .watch(
                    &path,
                    notify_debouncer_full::notify::RecursiveMode::Recursive,
                )
                .map(|()| debouncer)
        });

        // Held for the life of the loop: dropping the debouncer stops the watch.
        let _debouncer = match watching {
            Ok(debouncer) => debouncer,
            Err(e) => {
                log_error_with_context!(e, "Failed to watch {:?}; the change feed stays off", path);
                return;
            }
        };

        if cfg!(windows) {
            log_warn!("The change feed is not supported on Windows and stays off");
        } else {
            state.store.go_live();
        }

        receive_fs_events(rx, &state).await;
    });
}

// Keep the receive loop shared with error-injection tests: calling Feed::fail
// directly would not catch stale cache entries after events were lost.
async fn receive_fs_events(
    mut rx: tokio::sync::mpsc::Receiver<notify_debouncer_full::DebounceEventResult>,
    state: &AppState,
) {
    while let Some(res) = rx.recv().await {
        match res {
            Ok(events) => utils::cache::handle_fs_events(&events, &state.store).await,
            Err(errors) => {
                for e in errors {
                    log_error_with_context!(e, "watch receive error; the change feed stops");
                }

                state.store.invalidate_all();
                state.store.feed().fail();
            }
        }
    }
}

#[cfg(feature = "stats")]
fn start_cache_statistics_logger(state: std::sync::Arc<AppState>) {
    tokio::spawn(async move {
        const STATS_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
        let mut interval = tokio::time::interval(STATS_LOG_INTERVAL);

        // Skip the first tick that completes immediately
        interval.tick().await;

        loop {
            interval.tick().await;

            let (hits, misses) = state.cache_stats.get();
            let total = hits + misses;

            if total == 0 {
                log_info!("Cache Statistics: No data yet (Hits=0, Misses=0)");
                continue;
            }

            // Calculate hit rate using integer arithmetic to avoid precision loss
            // This gives us percentage with 2 decimal places (e.g., 9534 = 95.34%)
            let hit_rate_basis_points = hits.saturating_mul(10_000) / total;
            let whole_percent = hit_rate_basis_points / 100;
            let fractional_percent = hit_rate_basis_points % 100;

            log_info!(
                "Cache Statistics: Hits={hits}, Misses={misses}, Hit Rate={whole_percent}.{fractional_percent:02}%, Total={total}"
            );
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{self, Request},
    };
    use generated::blorg_meta_flat::{Directory, DirectoryEntryMetadata};
    use http_body_util::BodyExt;
    use std::fs::{self, File};
    use std::io::Write;
    use std::sync::Arc;
    use tower::{Service, util::ServiceExt};

    // Warm resolution must never authorise a later open through a replaced
    // ancestor. Exercise the router and collect the body: checking only a
    // canonicalisation helper would miss ServeFile's second pathname open.
    #[cfg(unix)]
    #[tokio::test]
    async fn warm_streamed_paths_cannot_escape_through_a_replaced_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("dir")).unwrap();
        fs::write(root.path().join("dir/file.txt"), b"inside").unwrap();
        fs::write(outside.path().join("file.txt"), b"outside secret").unwrap();
        let state = Arc::new(
            AppState::new(
                root.path(),
                utils::cache::Config {
                    max_resident_file_bytes: 0,
                    ..utils::cache::Config::default()
                },
            )
            .unwrap(),
        );
        let app = build_router(state);
        let warm = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/get_file?path=dir/file.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(warm.status(), http::StatusCode::OK);
        assert_eq!(
            warm.into_body().collect().await.unwrap().to_bytes(),
            "inside"
        );
        fs::rename(root.path().join("dir"), root.path().join("old")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("dir")).unwrap();
        for method in [http::Method::GET, http::Method::HEAD] {
            for path in [
                "dir/file.txt",
                "dir%2Ffile.txt",
                "dir/./file.txt",
                "dir%5Cfile.txt",
            ] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method.clone())
                            .uri(format!("/get_file?path={path}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    http::StatusCode::FORBIDDEN,
                    "{method} {path}"
                );
                assert!(!response.headers().contains_key(http::header::ETAG));
                assert!(!response.headers().contains_key(http::header::LAST_MODIFIED));
            }
        }
    }

    // Metadata can warm a resolution without loading content or the child's
    // own listing. Both subsequent cache loaders must use the root boundary.
    #[cfg(unix)]
    #[tokio::test]
    async fn warm_metadata_paths_confine_resident_and_directory_loaders() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("dir/sub")).unwrap();
        fs::create_dir(outside.path().join("sub")).unwrap();
        fs::write(root.path().join("dir/file.txt"), b"inside").unwrap();
        fs::write(outside.path().join("file.txt"), b"outside secret").unwrap();
        fs::write(outside.path().join("sub/secret.txt"), b"secret").unwrap();
        let state = Arc::new(AppState::new(root.path(), utils::cache::Config::default()).unwrap());
        let app = build_router(state);
        for path in ["dir/file.txt", "dir/sub"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/get_dir_entry_info?path={path}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
        }
        fs::rename(root.path().join("dir"), root.path().join("old")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("dir")).unwrap();
        for uri in [
            "/get_file?path=dir/file.txt",
            "/get_dir_info?path=dir/sub",
            "/get_dir_info?path=dir/sub&subtree=64",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::FORBIDDEN, "{uri}");
        }
    }

    // Rejection must be about leaving the export namespace. A cached name
    // replaced with a symlink to another in-root directory remains usable.
    #[cfg(unix)]
    #[tokio::test]
    async fn warm_streamed_paths_accept_in_root_ancestor_replacements() {
        for absolute in [false, true] {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir(root.path().join("dir")).unwrap();
            fs::write(root.path().join("dir/file.txt"), b"inside").unwrap();
            let state = Arc::new(
                AppState::new(
                    root.path(),
                    utils::cache::Config {
                        max_resident_file_bytes: 0,
                        ..utils::cache::Config::default()
                    },
                )
                .unwrap(),
            );
            let app = build_router(state);
            let request = || {
                Request::builder()
                    .uri("/get_file?path=dir/file.txt")
                    .body(Body::empty())
                    .unwrap()
            };
            let response = app.clone().oneshot(request()).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            fs::rename(root.path().join("dir"), root.path().join("moved")).unwrap();
            let target = if absolute {
                root.path().join("moved")
            } else {
                "moved".into()
            };
            std::os::unix::fs::symlink(target, root.path().join("dir")).unwrap();
            let response = app.oneshot(request()).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "inside"
            );
        }
    }

    // Pin the streaming contract independently of resident response assembly:
    // its preconditions and malformed/multipart range behavior differ.
    fn conditional_file_app(max_resident_file_bytes: u64) -> (tempfile::TempDir, Router) {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("file #%.txt"), b"abcdefghij").unwrap();
        File::options()
            .write(true)
            .open(root.path().join("file #%.txt"))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000),
            ))
            .unwrap();
        let app = build_router(Arc::new(
            AppState::new(
                root.path(),
                utils::cache::Config {
                    max_resident_file_bytes,
                    ..utils::cache::Config::default()
                },
            )
            .unwrap(),
        ));
        (root, app)
    }

    async fn file_response(
        app: &Router,
        method: http::Method,
        headers: &[(http::header::HeaderName, String)],
    ) -> http::Response<Body> {
        let mut request = Request::builder()
            .uri("/get_file?path=file%20%23%25.txt")
            .method(method);
        for (name, value) in headers {
            request = request.header(name.clone(), value);
        }
        app.clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn confined_streams_keep_conditional_range_and_head_contracts() {
        let (_root, app) = conditional_file_app(0);
        let response = file_response(&app, http::Method::GET, &[]).await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.headers()[http::header::CONTENT_TYPE], "text/plain");
        let etag = response.headers()[http::header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        for (name, value, status) in [
            (http::header::IF_MATCH, etag.clone(), http::StatusCode::OK),
            (
                http::header::IF_MATCH,
                "\"other\"".to_owned(),
                http::StatusCode::PRECONDITION_FAILED,
            ),
            (
                http::header::IF_NONE_MATCH,
                format!("\"other\", W/{etag}"),
                http::StatusCode::NOT_MODIFIED,
            ),
            (
                http::header::IF_UNMODIFIED_SINCE,
                "Wed, 21 Oct 2015 07:28:00 GMT".to_owned(),
                http::StatusCode::PRECONDITION_FAILED,
            ),
            (
                http::header::IF_MODIFIED_SINCE,
                "Mon, 21 Oct 2030 07:28:00 GMT".to_owned(),
                http::StatusCode::NOT_MODIFIED,
            ),
            (
                http::header::RANGE,
                "bytes=20-30".to_owned(),
                http::StatusCode::RANGE_NOT_SATISFIABLE,
            ),
            (
                http::header::RANGE,
                "bytes=oops".to_owned(),
                http::StatusCode::RANGE_NOT_SATISFIABLE,
            ),
            (
                http::header::RANGE,
                "bytes=0-1,4-5".to_owned(),
                http::StatusCode::RANGE_NOT_SATISFIABLE,
            ),
        ] {
            let response = file_response(&app, http::Method::GET, &[(name, value)]).await;
            assert_eq!(response.status(), status);
            response.into_body().collect().await.unwrap();
        }
        for method in [http::Method::GET, http::Method::HEAD] {
            let response = file_response(
                &app,
                method.clone(),
                &[(http::header::RANGE, "bytes=2-4".to_owned())],
            )
            .await;
            assert_eq!(response.status(), http::StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                response.headers()[http::header::CONTENT_RANGE],
                "bytes 2-4/10"
            );
            assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "3");
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let expected: &[u8] = if method == http::Method::HEAD {
                b""
            } else {
                b"cde"
            };
            assert_eq!(bytes.as_ref(), expected);
        }
    }

    // Resident responses use a different range/validator implementation from
    // tower's streamed service. Exercise both headers and bytes through the router.
    #[tokio::test]
    async fn resident_responses_obey_validators_ranges_and_head() {
        let (_root, app) = conditional_file_app(1024);
        let response = file_response(&app, http::Method::GET, &[]).await;
        let etag = response.headers()[http::header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "abcdefghij"
        );
        for (name, value) in [
            (http::header::IF_NONE_MATCH, etag),
            (http::header::IF_NONE_MATCH, "*".to_owned()),
            (
                http::header::IF_MODIFIED_SINCE,
                "Mon, 21 Oct 2030 07:28:00 GMT".to_owned(),
            ),
        ] {
            let response = file_response(
                &app,
                http::Method::GET,
                &[(name, value), (http::header::RANGE, "bytes=2-4".to_owned())],
            )
            .await;
            assert_eq!(response.status(), http::StatusCode::NOT_MODIFIED);
            assert!(!response.headers().contains_key(http::header::CONTENT_RANGE));
            assert!(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .is_empty()
            );
        }
        let response = file_response(
            &app,
            http::Method::GET,
            &[
                (http::header::IF_NONE_MATCH, "\"other\"".to_owned()),
                (
                    http::header::IF_MODIFIED_SINCE,
                    "Mon, 21 Oct 2030 07:28:00 GMT".to_owned(),
                ),
            ],
        )
        .await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "abcdefghij"
        );
        let response = file_response(
            &app,
            http::Method::GET,
            &[(http::header::RANGE, "bytes=20-30".to_owned())],
        )
        .await;
        assert_eq!(response.status(), http::StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response.headers()[http::header::CONTENT_RANGE],
            "bytes */10"
        );
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        for method in [http::Method::GET, http::Method::HEAD] {
            let response = file_response(
                &app,
                method.clone(),
                &[(http::header::RANGE, "bytes=2-4".to_owned())],
            )
            .await;
            assert_eq!(response.status(), http::StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                response.headers()[http::header::CONTENT_RANGE],
                "bytes 2-4/10"
            );
            assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "3");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let expected: &[u8] = if method == http::Method::HEAD {
                b""
            } else {
                b"cde"
            };
            assert_eq!(body.as_ref(), expected);
        }
    }

    // Once the router has confined its open, changing the pathname must not
    // redirect the streaming service. The response must consume that handle.
    #[cfg(unix)]
    #[tokio::test]
    async fn streaming_uses_the_confined_handle_after_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = root.path().join("file.txt");
        fs::write(&path, b"inside").unwrap();
        fs::write(outside.path().join("file.txt"), b"outside secret").unwrap();
        let state = AppState::new(root.path(), utils::cache::Config::default()).unwrap();
        let file = state.store.open_file(&path).await.unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(outside.path().join("file.txt"), &path).unwrap();
        let response = utils::http::streamed_response(
            file,
            &path,
            Request::builder()
                .uri("/get_file?path=file.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "6");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "inside"
        );
    }

    mod extract_path {
        use super::*;

        fn uri(raw: &str) -> axum::http::Uri {
            raw.parse().unwrap()
        }

        #[test]
        fn reads_the_value_of_path() {
            assert_eq!(
                super::extract_path(&uri("/get_file?path=a/b.txt")).unwrap(),
                "a/b.txt"
            );
        }

        #[test]
        fn borrows_when_there_is_nothing_to_decode() {
            // The point of returning `Cow`: an already-clean value costs no
            // allocation to extract.
            assert!(matches!(
                super::extract_path(&uri("/get_file?path=a/b.txt")).unwrap(),
                std::borrow::Cow::Borrowed(_)
            ));
        }

        #[test]
        fn decodes_percent_escapes() {
            assert_eq!(
                super::extract_path(&uri("/get_file?path=a%20b%2Fc")).unwrap(),
                "a b/c"
            );
        }

        #[test]
        fn finds_path_among_other_params() {
            assert_eq!(
                super::extract_path(&uri("/get_file?a=1&path=x.txt&b=2")).unwrap(),
                "x.txt"
            );
        }

        #[test]
        fn missing_key_is_a_bad_request() {
            assert_eq!(
                super::extract_path(&uri("/get_file?other=1")),
                Err(AppError::BadRequest)
            );
            assert_eq!(
                super::extract_path(&uri("/get_file")),
                Err(AppError::BadRequest)
            );
        }

        #[test]
        fn invalid_utf8_after_decoding_is_a_bad_request() {
            // %ff is not valid UTF-8 on its own.
            assert_eq!(
                super::extract_path(&uri("/get_file?path=%ff")),
                Err(AppError::BadRequest)
            );
        }

        #[test]
        fn empty_value_is_the_served_root() {
            // `path=` with nothing after it is how a client asks for the root -
            // distinct from the key being absent entirely.
            assert_eq!(super::extract_path(&uri("/get_file?path=")).unwrap(), "");
        }
    }

    // Test setup helper
    fn setup_test_env(base_dir: &std::path::Path) -> Arc<AppState> {
        // Create test files
        fs::create_dir(base_dir.join("test_dir")).unwrap();
        File::create(base_dir.join("test_file.txt"))
            .unwrap()
            .write_all(b"test content")
            .unwrap();
        File::create(base_dir.join("test_dir/file_in_dir.txt"))
            .unwrap()
            .write_all(b"nested content")
            .unwrap();
        fs::create_dir(base_dir.join("test_dir/nested_test_dir")).unwrap();
        fs::create_dir(base_dir.join("other_test_dir")).unwrap();
        File::create(base_dir.join("test_dir/nested_test_dir/file_in_nested_test_dir.txt"))
            .unwrap()
            .write_all(b"nested content")
            .unwrap();

        // Long enough that nothing expires mid-test: tests that care about
        // eviction set their own TTL via `setup_test_env_with_cache_config`.
        state_with_config(
            base_dir,
            utils::cache::Config {
                time_to_live: std::time::Duration::from_mins(2),
                time_to_idle: std::time::Duration::from_mins(2),
                ..utils::cache::Config::default()
            },
        )
    }

    fn state_with_config(
        base_dir: &std::path::Path,
        config: utils::cache::Config,
    ) -> Arc<AppState> {
        Arc::new(AppState::new(base_dir, config).unwrap())
    }

    /// The canonical form of a path under the served root - which is what the
    /// cache is keyed by, so it is what probes have to be asked about.
    fn canonical(state: &AppState, relative: &str) -> std::path::PathBuf {
        if relative.is_empty() {
            state.store.base().to_path_buf()
        } else {
            state.store.base().join(relative)
        }
    }

    mod misc {
        use super::*;

        #[tokio::test]
        async fn test_timestamps_consistency() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);

            // Create a directory with one subdirectory
            let parent_dir = temp_dir.join("timestamp_test");
            fs::create_dir(&parent_dir).unwrap();
            let sub_dir = parent_dir.join("subdirectory");
            fs::create_dir(&sub_dir).unwrap();

            // Add a file to parent directory for comparison
            let file_path = parent_dir.join("test_file.txt");
            File::create(&file_path)
                .unwrap()
                .write_all(b"test")
                .unwrap();

            // Get original metadata
            let subdir_meta = fs::metadata(&sub_dir).unwrap();
            let file_meta = fs::metadata(&file_path).unwrap();

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state);

            // Test directory listing
            let req = Request::builder()
                .uri("/get_dir_info?path=timestamp_test")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            let bytes = resp.collect().await.unwrap().to_bytes();
            let fb_dir: Directory = flatbuffers::root::<Directory>(&bytes).unwrap();

            // Test file info
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=timestamp_test/test_file.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            let bytes = resp.collect().await.unwrap().to_bytes();
            let fb_file = flatbuffers::root::<DirectoryEntryMetadata>(&bytes).unwrap();

            // Verify file timestamps from get_dir_entry_info
            let file_created_expected = crate::utils::windows::time::IntoFileTime::into_file_time(
                file_meta.created().unwrap(),
            );
            let file_modified_expected = crate::utils::windows::time::IntoFileTime::into_file_time(
                file_meta.modified().unwrap(),
            );

            assert_eq!(fb_file.created(), file_created_expected);
            assert_eq!(fb_file.modified(), file_modified_expected);

            // Find file in directory listing
            let file_index = fb_dir
                .files()
                .unwrap()
                .iter()
                .position(|n| n.name().unwrap() == "test_file.txt")
                .unwrap();

            // Verify file timestamps from directory listing
            assert_eq!(
                fb_dir.files().unwrap().get(file_index).created(),
                file_created_expected
            );
            assert_eq!(
                fb_dir.files().unwrap().get(file_index).modified(),
                file_modified_expected
            );

            // Verify subdirectory timestamps
            let subdir_created_expected = crate::utils::windows::time::IntoFileTime::into_file_time(
                subdir_meta.created().unwrap(),
            );
            let subdir_modified_expected =
                crate::utils::windows::time::IntoFileTime::into_file_time(
                    subdir_meta.modified().unwrap(),
                );

            let dir_index = fb_dir
                .subdirectories()
                .unwrap()
                .iter()
                .position(|n| n.name().unwrap() == "subdirectory")
                .unwrap();

            assert_eq!(
                fb_dir.subdirectories().unwrap().get(dir_index).created(),
                subdir_created_expected
            );
            assert_eq!(
                fb_dir.subdirectories().unwrap().get(dir_index).modified(),
                subdir_modified_expected
            );
        }

        #[tokio::test]
        async fn test_concurrent_cache_access() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);

            let app = Arc::new(
                Router::new()
                    .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                    .with_state(state.clone()),
            );

            // Spawn multiple tasks to hit the same cache concurrently
            let mut handles = Vec::new();
            for _ in 0..50 {
                let app_clone = app.clone();
                let handle = tokio::spawn(async move {
                    let req = Request::builder()
                        .uri("/get_dir_info?path=test_dir")
                        .method("GET")
                        .body(Body::empty())
                        .unwrap();

                    let resp = <axum::Router as Clone>::clone(&app_clone)
                        .oneshot(req)
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), http::StatusCode::OK);
                });
                handles.push(handle);
            }

            futures::future::join_all(handles).await;

            #[cfg(feature = "stats")]
            {
                let (hits, misses) = state.cache_stats.get();
                assert!(hits + misses > 0);
            }
        }
    }

    mod dir_entry_info {
        use super::*;

        #[tokio::test]
        async fn test_valid_file_info() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state);

            let req = Request::builder()
                .uri("/get_dir_entry_info?path=test_file.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            let bytes = resp.collect().await.unwrap().to_bytes();
            // Parse FlatBuffer data
            let fb_data: DirectoryEntryMetadata =
                flatbuffers::root::<DirectoryEntryMetadata>(&bytes).unwrap();

            assert_eq!(fb_data.size(), 12);
        }

        #[tokio::test]
        async fn test_nonexistent_file_info() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state);

            let req = Request::builder()
                .uri("/get_dir_entry_info?path=nonexistent.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_deep_nested_directories() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);
            let mut path = temp_dir.to_path_buf();
            for depth in 0..10 {
                path = path.join(format!("level_{depth}"));
                fs::create_dir(&path).unwrap();
            }
            File::create(path.join("deep_file.txt")).unwrap();

            let app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state);

            let req = Request::builder()
        .uri("/get_dir_entry_info?path=level_0/level_1/level_2/level_3/level_4/level_5/level_6/level_7/level_8/level_9/deep_file.txt")
        .method("GET")
        .body(Body::empty())
        .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        #[tokio::test]
        async fn test_folder_and_data_changes() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);
            let directory_path = temp_dir.join("test_dir");

            // obtain file metadata like creation time
            let metadata = fs::metadata(&directory_path).unwrap();

            let created_secs = crate::utils::windows::time::IntoFileTime::into_file_time(
                metadata.created().unwrap(),
            );

            let modified_secs = crate::utils::windows::time::IntoFileTime::into_file_time(
                metadata.modified().unwrap(),
            );

            let mut app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state.clone());

            // Initial request to populate cache
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();

            let bytes = resp.collect().await.unwrap().to_bytes();

            let fb_data: DirectoryEntryMetadata =
                flatbuffers::root::<DirectoryEntryMetadata>(&bytes).unwrap();

            assert_eq!(fb_data.size(), metadata.len());
            assert_eq!(fb_data.created(), created_secs);
            assert_eq!(fb_data.modified(), modified_secs);
            assert!(fb_data.directory());
        }
    }

    mod directory_info {
        use super::*;

        #[tokio::test]
        async fn test_directory_info() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::OK);

            let bytes = resp.collect().await.unwrap().to_bytes();

            // Parse FlatBuffer data
            let fb_data: Directory = flatbuffers::root::<Directory>(&bytes).unwrap();

            let directory_count = fb_data.subdirectories().unwrap().len();
            let file_count = fb_data.files().unwrap().len();

            assert_eq!(directory_count, 1);

            assert_eq!(file_count, 1);

            assert_eq!(
                fb_data.files().unwrap().get(0).name().unwrap(),
                "file_in_dir.txt"
            );
        }

        async fn subtree(budget: &str) -> bytes::Bytes {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());

            let req = Request::builder()
                .uri(format!("/get_dir_info?path=&subtree={budget}"))
                .body(Body::empty())
                .unwrap();

            let resp = build_router(state).oneshot(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            resp.collect().await.unwrap().to_bytes()
        }

        /// `(parent, subdirectory, name, entries)` for each descendant, the
        /// name looked up through the parent the way a client has to.
        fn descendants(bytes: &[u8]) -> Vec<(u32, u32, String, usize)> {
            let root = flatbuffers::root::<Directory>(bytes).unwrap();
            let mut listings = vec![root];
            let mut out = Vec::new();

            for descendant in root.descendants().into_iter().flatten() {
                let parent = listings[descendant.parent() as usize];
                let name = parent
                    .subdirectories()
                    .unwrap()
                    .get(descendant.subdirectory() as usize)
                    .name()
                    .unwrap()
                    .to_owned();
                let listing = descendant.listing().unwrap();
                let entries = listing.subdirectories().unwrap().len() + listing.files().unwrap().len();

                assert!(listing.descendants().is_none());
                out.push((descendant.parent(), descendant.subdirectory(), name, entries));
                listings.push(listing);
            }

            out
        }

        #[tokio::test]
        async fn a_subtree_carries_every_listing_beneath_breadth_first() {
            let bytes = subtree("100").await;

            assert_eq!(
                descendants(&bytes),
                vec![
                    (0, 0, "other_test_dir".to_owned(), 0),
                    (0, 1, "test_dir".to_owned(), 2),
                    (2, 0, "nested_test_dir".to_owned(), 1),
                ]
            );
        }

        #[tokio::test]
        async fn a_subtree_stops_at_the_first_listing_over_budget() {
            // The root's three entries, then one for the empty directory and
            // three for test_dir: nested_test_dir's two do not fit.
            let bytes = subtree("7").await;

            assert_eq!(
                descendants(&bytes),
                vec![
                    (0, 0, "other_test_dir".to_owned(), 0),
                    (0, 1, "test_dir".to_owned(), 2),
                ]
            );
        }

        #[tokio::test]
        async fn a_subtree_wider_than_a_batch_keeps_breadth_first_order() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());

            for i in 0..40 {
                std::fs::create_dir_all(temp.path().join(format!("wide/d{i:02}/s"))).unwrap();
            }

            // The root's forty entries, two for each d, then one for each of
            // the first five s.
            let req = Request::builder()
                .uri("/get_dir_info?path=wide&subtree=125")
                .body(Body::empty())
                .unwrap();

            let resp = build_router(state).oneshot(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            let bytes = resp.collect().await.unwrap().to_bytes();
            let expected: Vec<_> = (0..40)
                .map(|i| (0, i, format!("d{i:02}"), 1))
                .chain((0..5).map(|i| (i + 1, 0, "s".to_owned(), 0)))
                .collect();

            assert_eq!(descendants(&bytes), expected);
        }

        #[tokio::test]
        async fn a_listing_without_subtree_carries_no_descendants() {
            let bytes = subtree("0").await;
            let root = flatbuffers::root::<Directory>(&bytes).unwrap();

            assert_eq!(root.subdirectories().unwrap().len(), 2);
            assert!(root.descendants().is_none());
        }

        #[test]
        fn a_subtree_budget_is_capped() {
            let budget = |query: &str| {
                let uri = format!("/get_dir_info?path={query}").parse().unwrap();
                subtree_budget(&uri)
            };

            assert_eq!(budget(""), 0);
            assert_eq!(budget("&subtree=7"), 7);
            assert_eq!(budget("&subtree=65537"), SUBTREE_MAX_ENTRIES);
            let max = u64::MAX;
            assert_eq!(budget(&format!("&subtree={max}")), SUBTREE_MAX_ENTRIES);
        }

        async fn subtree_of(state: &Arc<AppState>, path: &str) -> axum::response::Response {
            let req = Request::builder()
                .uri(format!("/get_dir_info?path={path}&subtree=100"))
                .body(Body::empty())
                .unwrap();

            let resp = build_router(state.clone()).oneshot(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            resp
        }

        fn no_store(resp: &axum::response::Response) -> bool {
            resp.headers().contains_key(http::header::CACHE_CONTROL)
        }

        #[tokio::test]
        async fn a_subtree_leaves_out_a_directory_that_can_no_longer_be_resolved() {
            // The cached root listing still names test_dir; asking for it
            // alone would answer 404, so the subtree goes on without it.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            state.store.directory_listing("").await.unwrap();
            fs::remove_dir_all(temp.path().join("test_dir")).unwrap();

            let resp = subtree_of(&state, "").await;
            let bytes = resp.collect().await.unwrap().to_bytes();

            assert_eq!(
                descendants(&bytes),
                vec![(0, 0, "other_test_dir".to_owned(), 0)]
            );
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn a_subtree_leaves_out_a_directory_no_request_could_name() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            fs::create_dir(temp.path().join("back\\slash")).unwrap();

            let resp = subtree_of(&state, "").await;
            let bytes = resp.collect().await.unwrap().to_bytes();

            assert_eq!(
                descendants(&bytes),
                vec![
                    (0, 1, "other_test_dir".to_owned(), 0),
                    (0, 2, "test_dir".to_owned(), 2),
                    (2, 0, "nested_test_dir".to_owned(), 1),
                ]
            );
        }

        #[tokio::test]
        async fn a_subtree_leaves_out_a_listing_a_generation_overtook() {
            // Folding it in would make the whole answer no-store; leaving it,
            // and what is beneath it, out keeps the rest cacheable.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let directory = canonical(&state, "test_dir");
            state.store.feed().begin();
            state.store.plant_directory(&directory, 0).await;

            let resp = subtree_of(&state, "").await;
            assert!(!no_store(&resp));

            let bytes = resp.collect().await.unwrap().to_bytes();
            assert_eq!(
                descendants(&bytes),
                vec![(0, 0, "other_test_dir".to_owned(), 0)]
            );
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn a_subtree_leaves_out_a_listing_reached_through_a_symlink() {
            // The cached root listing names other_test_dir as a directory,
            // but it now resolves into test_dir, which the watcher would
            // report under test_dir's name.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            state.store.directory_listing("").await.unwrap();
            fs::remove_dir(temp.path().join("other_test_dir")).unwrap();
            std::os::unix::fs::symlink(
                temp.path().join("test_dir"),
                temp.path().join("other_test_dir"),
            )
            .unwrap();

            let resp = subtree_of(&state, "").await;
            assert!(!no_store(&resp));

            let bytes = resp.collect().await.unwrap().to_bytes();
            assert_eq!(
                descendants(&bytes),
                vec![
                    (0, 1, "test_dir".to_owned(), 2),
                    (1, 0, "nested_test_dir".to_owned(), 1),
                ]
            );
        }

        #[tokio::test]
        async fn test_special_char_filenames() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);
            let file_names = vec!["файл.txt", "スペース ファイル", "😀.md"];

            for name in &file_names {
                File::create(temp_dir.join(name)).unwrap();
            }

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/get_dir_info?path=.")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            let bytes = resp.collect().await.unwrap().to_bytes();

            let fb_data: Directory = flatbuffers::root::<Directory>(&bytes).unwrap();
            let entries = fb_data.files().unwrap();

            for name in file_names {
                assert!(entries.iter().any(|e| e.name().unwrap() == name));
            }
        }

        #[tokio::test]
        async fn test_directory_with_mixed_contents() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            // Create directory with multiple subdirectories and files
            let mixed_dir = temp_dir.join("mixed_dir");
            fs::create_dir(&mixed_dir).unwrap();

            // Create subdirectories
            for i in 1..=3 {
                fs::create_dir(mixed_dir.join(format!("subdir_{i}"))).unwrap();
            }

            // Create files
            for i in 1..=5 {
                File::create(mixed_dir.join(format!("file_{i}.txt")))
                    .unwrap()
                    .write_all(format!("content {i}").as_bytes())
                    .unwrap();
            }

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/get_dir_info?path=mixed_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::OK);

            let bytes = resp.collect().await.unwrap().to_bytes();

            // Parse FlatBuffer data
            let fb_data: Directory = flatbuffers::root::<Directory>(&bytes).unwrap();

            // Verify counts
            assert_eq!(fb_data.subdirectories().unwrap().len(), 3);
            assert_eq!(fb_data.files().unwrap().len(), 5);

            // Verify directory names are present
            let dir_names_set: std::collections::HashSet<&str> = fb_data
                .subdirectories()
                .unwrap()
                .iter()
                .map(|e| e.name().unwrap())
                .collect();
            assert!(dir_names_set.contains("subdir_1"));
            assert!(dir_names_set.contains("subdir_2"));
            assert!(dir_names_set.contains("subdir_3"));

            // Verify file names are present
            let file_names_set: std::collections::HashSet<&str> = fb_data
                .files()
                .unwrap()
                .iter()
                .map(|e| e.name().unwrap())
                .collect();
            assert!(file_names_set.contains("file_1.txt"));
            assert!(file_names_set.contains("file_2.txt"));
            assert!(file_names_set.contains("file_3.txt"));
            assert!(file_names_set.contains("file_4.txt"));
            assert!(file_names_set.contains("file_5.txt"));
        }

        #[tokio::test]
        async fn test_directory_metadata_fields() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            // Create nested directory structure with specific timestamps if possible
            let nested_dir = temp_dir.join("nested_test_dir");
            fs::create_dir(&nested_dir).unwrap();

            // Add a subdirectory to test with
            let sub_dir = nested_dir.join("sub_directory");
            fs::create_dir(&sub_dir).unwrap();

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/get_dir_info?path=nested_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::OK);

            let bytes = resp.collect().await.unwrap().to_bytes();

            // Parse FlatBuffer data
            let fb_data: Directory = flatbuffers::root::<Directory>(&bytes).unwrap();

            // Verify there's one directory and no files
            assert_eq!(fb_data.subdirectories().unwrap().len(), 1);
            assert_eq!(fb_data.files().unwrap().len(), 0);

            // Verify directory name
            assert_eq!(
                fb_data.subdirectories().unwrap().get(0).name().unwrap(),
                "sub_directory"
            );

            // Check that times are in the expected range (non-zero and recent)
            let created = fb_data.subdirectories().unwrap().get(0).created();
            let modified = fb_data.subdirectories().unwrap().get(0).modified();
            let accessed = fb_data.subdirectories().unwrap().get(0).accessed();

            assert!(created > 0);
            assert!(modified > 0);
            assert!(accessed > 0);
        }
    }

    mod file_download {
        use super::*;

        #[tokio::test]
        async fn test_file_download() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let app = Router::new()
                .route("/get_file", axum::routing::get(get_file_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/get_file?path=test_file.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::OK);
            let bytes = resp.collect().await.unwrap().to_bytes();
            assert_eq!(bytes, "test content");
        }

        #[tokio::test]
        async fn test_file_download_range() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let app = Router::new()
                .route("/get_file", axum::routing::get(get_file_handler))
                .with_state(state);

            // --- Test Case 1: Request bytes 5-9 ---
            // Corresponds to "conte" from "test content"
            let req_range_1 = Request::builder()
                .uri("/get_file?path=test_file.txt")
                .method("GET")
                .header(http::header::RANGE, "bytes=5-9") // Request specific range
                .body(Body::empty()) // Use axum::body::Body
                .unwrap();

            let resp_range_1 = app.clone().oneshot(req_range_1).await.unwrap();

            // Assertions for successful range request
            assert_eq!(resp_range_1.status(), http::StatusCode::PARTIAL_CONTENT);

            // Check the Content-Range header
            let headers_1 = resp_range_1.headers();
            assert_eq!(
                headers_1
                    .get(http::header::CONTENT_RANGE)
                    .expect("Response should have Content-Range header")
                    .to_str()
                    .unwrap(),
                "bytes 5-9/12" // Range served (5-9) and total size (12)
            );

            let bytes_1 = resp_range_1.collect().await.unwrap().to_bytes();
            assert_eq!(bytes_1, "conte");

            // --- Test Case 2: Request last 4 bytes ---
            // Corresponds to "tent" from "test content"
            let req_range_2 = Request::builder()
                .uri("/get_file?path=test_file.txt")
                .method("GET")
                .header(http::header::RANGE, "bytes=-4") // Request suffix range
                .body(Body::empty())
                .unwrap();

            let resp_range_2 = app.clone().oneshot(req_range_2).await.unwrap();

            assert_eq!(resp_range_2.status(), http::StatusCode::PARTIAL_CONTENT);

            // Check the Content-Range header (bytes 8-11 for a 12-byte file)
            let headers_2 = resp_range_2.headers();
            assert_eq!(
                headers_2
                    .get(http::header::CONTENT_RANGE)
                    .expect("Response should have Content-Range header")
                    .to_str()
                    .unwrap(),
                "bytes 8-11/12" // Range served (8-11) and total size (12)
            );

            let bytes_2 = resp_range_2.collect().await.unwrap().to_bytes();
            assert_eq!(bytes_2, "tent"); // Only the requested part

            // --- Test Case 3: Request from byte 8 to end ---
            // Corresponds to "tent" from "test content"
            let req_range_3 = Request::builder()
                .uri("/get_file?path=test_file.txt")
                .method("GET")
                .header(http::header::RANGE, "bytes=8-") // Request prefix range
                .body(Body::empty()) // Use axum::body::Body
                .unwrap();

            let resp_range_3 = app.oneshot(req_range_3).await.unwrap();

            assert_eq!(resp_range_3.status(), http::StatusCode::PARTIAL_CONTENT);

            // Check the Content-Range header (bytes 8-11 for a 12-byte file)
            let headers_3 = resp_range_3.headers();
            assert_eq!(
                headers_3
                    .get(http::header::CONTENT_RANGE)
                    .expect("Response should have Content-Range header")
                    .to_str()
                    .unwrap(),
                "bytes 8-11/12"
            );

            let bytes_3 = resp_range_3.collect().await.unwrap().to_bytes();
            assert_eq!(bytes_3, "tent");
        }

        #[tokio::test]
        async fn test_file_download_head() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let app = Router::new()
                .route("/get_file", axum::routing::head(get_file_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/get_file?path=test_file.txt")
                .method("HEAD")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::OK);
            assert_eq!(
                resp.headers()
                    .get("Content-Length")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "12"
            );
            let bytes = resp.collect().await.unwrap().to_bytes();
            assert!(bytes.is_empty());
        }

        #[tokio::test]
        async fn a_file_carries_one_entity_tag_resident_or_streamed() {
            let temp = tempfile::tempdir().unwrap();
            let resident = setup_test_env(temp.path());
            let streamed = state_with_config(
                temp.path(),
                utils::cache::Config {
                    max_resident_file_bytes: 0,
                    ..utils::cache::Config::default()
                },
            );

            let mut tags = Vec::new();

            for state in [resident, streamed] {
                let req = Request::builder()
                    .uri("/get_file?path=test_file.txt")
                    .header(http::header::RANGE, "bytes=0-3")
                    .body(Body::empty())
                    .unwrap();

                let resp = build_router(state).oneshot(req).await.unwrap();
                assert_eq!(resp.status(), http::StatusCode::PARTIAL_CONTENT);
                tags.push(resp.headers().get(http::header::ETAG).cloned().unwrap());
            }

            let since = fs::metadata(temp.path().join("test_file.txt"))
                .unwrap()
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            let expected = format!("\"{:x}.{:08x}-c\"", since.as_secs(), since.subsec_nanos());

            assert_eq!(tags[0], expected);
            assert_eq!(tags[1], expected);
        }
    }

    mod cache {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        use tokio::time::timeout;

        // Helper to create cache with specific TTL for testing
        fn setup_test_env_with_cache_config(
            base_dir: &std::path::Path,
            ttl_secs: u64,
            idle_secs: u64,
        ) -> Arc<AppState> {
            // Create test files
            fs::create_dir(base_dir.join("test_dir")).unwrap();
            File::create(base_dir.join("test_file.txt"))
                .unwrap()
                .write_all(b"test content")
                .unwrap();
            File::create(base_dir.join("test_dir/file_in_dir.txt"))
                .unwrap()
                .write_all(b"nested content")
                .unwrap();

            state_with_config(
                base_dir,
                utils::cache::Config {
                    time_to_live: Duration::from_secs(ttl_secs),
                    time_to_idle: Duration::from_secs(idle_secs),
                    ..utils::cache::Config::default()
                },
            )
        }

        #[cfg(feature = "stats")]
        #[tokio::test]
        async fn test_cache_hit_miss_behavior() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            // Verify initial state
            assert_eq!(state.cache_stats.get(), (0, 0));

            // First request - should be a cache miss
            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            let (hits, misses) = state.cache_stats.get();
            assert_eq!(hits, 0);
            assert_eq!(misses, 1);

            // Second request - should be a cache hit
            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            let (hits, misses) = state.cache_stats.get();
            assert_eq!(hits, 1);
            assert_eq!(misses, 1);

            // Third request - should be another cache hit
            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            let (hits, misses) = state.cache_stats.get();
            assert_eq!(hits, 2);
            assert_eq!(misses, 1);
        }

        #[cfg(feature = "stats")]
        #[tokio::test]
        async fn test_cache_different_paths() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            // Create additional directories
            fs::create_dir(temp_dir.join("dir1")).unwrap();
            fs::create_dir(temp_dir.join("dir2")).unwrap();

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            // Request different paths - each should be a cache miss initially
            for (i, path) in ["test_dir", "dir1", "dir2"].iter().enumerate() {
                let req = Request::builder()
                    .uri(format!("/get_dir_info?path={path}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();
                let resp = app.call(req).await.unwrap();
                assert_eq!(resp.status(), http::StatusCode::OK);

                let (hits, misses) = state.cache_stats.get();
                assert_eq!(hits, 0);
                assert_eq!(misses, (i + 1) as u64);
            }

            // Request same paths again - should be cache hits
            for (i, path) in ["test_dir", "dir1", "dir2"].iter().enumerate() {
                let req = Request::builder()
                    .uri(format!("/get_dir_info?path={path}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();
                let resp = app.call(req).await.unwrap();
                assert_eq!(resp.status(), http::StatusCode::OK);

                let (hits, misses) = state.cache_stats.get();
                assert_eq!(hits, (i + 1) as u64);
                assert_eq!(misses, 3);
            }
        }

        #[cfg(feature = "stats")]
        #[tokio::test]
        async fn test_file_cache() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            let file_a = String::from("a.txt");
            let file_b = String::from("b.txt");

            // Create additional directories
            File::create(temp_dir.join(&file_a))
                .unwrap()
                .write_all(b"stuff")
                .unwrap();
            File::create(temp_dir.join(&file_b))
                .unwrap()
                .write_all(b"stuff")
                .unwrap();

            let mut app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state.clone());

            let mut expected_misses = 0;

            // Request different paths - each should be a cache miss initially
            for path in &[&file_a, &file_b] {
                let req = Request::builder()
                    .uri(format!("/get_dir_entry_info?path={path}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();
                let resp = app.call(req).await.unwrap();
                assert_eq!(resp.status(), http::StatusCode::OK);

                let (hits, misses) = state.cache_stats.get();
                assert_eq!(hits, 0);

                expected_misses += 1;

                assert_eq!(misses, expected_misses);
            }

            // Request same paths again - should be cache hits
            for (i, path) in [file_a, file_b].iter().enumerate() {
                let req = Request::builder()
                    .uri(format!("/get_dir_entry_info?path={path}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();
                let resp = app.call(req).await.unwrap();
                assert_eq!(resp.status(), http::StatusCode::OK);

                let (hits, misses) = state.cache_stats.get();
                assert_eq!(hits, (i + 1) as u64);
                assert_eq!(misses, expected_misses);
            }
        }

        // There is no test here for TTL/TTI *expiry* itself: `moka` reads
        // `std::time::Instant::now()` internally rather than going through
        // `tokio::time`, so `tokio::time::pause`/`advance` cannot move its
        // clock, and the only way to observe real expiry would be a real
        // sleep. Expiry is `moka`'s contract, verified by its own test suite
        // against its own mockable clock - not observable, deterministically,
        // from outside the crate. What we own, and can and do assert
        // instantly, is that our `Config` is actually wired into every cache
        // tier `Store` builds: see
        // `utils::cache::tests::configured_durations_reach_every_cache_tier`.

        #[tokio::test]
        async fn test_concurrent_cache_access_stress() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            let app = Arc::new(
                Router::new()
                    .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                    .with_state(state.clone()),
            );

            let request_count = Arc::new(AtomicUsize::new(0));
            let error_count = Arc::new(AtomicUsize::new(0));

            // Spawn many concurrent tasks
            let mut handles = Vec::new();
            for _task_id in 0..100 {
                let app_clone = app.clone();
                let request_count_clone = request_count.clone();
                let error_count_clone = error_count.clone();

                let handle = tokio::spawn(async move {
                    // Each task makes multiple requests
                    for _ in 0..5 {
                        let req = Request::builder()
                            .uri("/get_dir_info?path=test_dir")
                            .method("GET")
                            .body(Body::empty())
                            .unwrap();

                        match timeout(
                            Duration::from_secs(5),
                            <axum::Router as Clone>::clone(&app_clone).oneshot(req),
                        )
                        .await
                        {
                            Ok(Ok(resp)) => {
                                if resp.status() == http::StatusCode::OK {
                                    request_count_clone.fetch_add(1, Ordering::SeqCst);
                                } else {
                                    error_count_clone.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            Ok(Err(_)) | Err(_) => {
                                error_count_clone.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                });
                handles.push(handle);
            }

            // Wait for all tasks to complete
            let results = futures::future::join_all(handles).await;

            // Verify no tasks panicked
            for result in results {
                result.unwrap();
            }

            // Verify we had successful requests and minimal errors
            let successful_requests = request_count.load(Ordering::SeqCst);
            let errors = error_count.load(Ordering::SeqCst);

            assert!(
                successful_requests > 0,
                "Should have some successful requests"
            );
            assert!(
                errors < successful_requests / 10,
                "Error rate should be low"
            );

            #[cfg(feature = "stats")]
            {
                let (hits, misses) = state.cache_stats.get();
                assert!(hits + misses > 0, "Should have cache activity");
                assert!(
                    hits > misses,
                    "Should have more hits than misses due to concurrency"
                );
            }
        }

        #[tokio::test]
        async fn test_cache_invalidation_manual() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            let path = canonical(&state, "test_dir");

            // Populate cache
            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            // Verify cache entry exists
            assert!(state.store.has_directory(&path));

            // Manually invalidate
            state.store.invalidate_directory(&path).await;

            // Verify entry is gone
            assert!(!state.store.has_directory(&path));
        }

        #[tokio::test]
        async fn test_cache_invalidation_after_file_modification() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            let file_path = temp_dir.join("modifiable.txt");
            File::create(&file_path).unwrap().write_all(b"v1").unwrap();

            // Caches are keyed by canonical path, so invalidation has to be
            // asked for in the same terms.
            let cache_key = canonical(&state, "modifiable.txt");

            let mut app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state.clone());

            // Initial request to populate cache
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=modifiable.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            let bytes = resp.collect().await.unwrap().to_bytes();
            let fb_data: DirectoryEntryMetadata =
                flatbuffers::root::<DirectoryEntryMetadata>(&bytes).unwrap();
            let original_size = fb_data.size();
            assert_eq!(original_size, 2);

            // The answer came out of the parent directory's node - there is no
            // separate per-file metadata cache to check.
            assert!(state.store.has_directory(state.store.base()));

            // Modify the file
            File::create(&file_path)
                .unwrap()
                .write_all(b"updated content")
                .unwrap();

            // Invalidate cache to simulate file watcher behavior
            state.store.invalidate_content(&cache_key).await;

            // Verify cache entry is gone
            assert!(!state.store.has_directory(state.store.base()));

            // Subsequent request should fetch fresh data
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=modifiable.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            let bytes = resp.collect().await.unwrap().to_bytes();
            let fb_data: DirectoryEntryMetadata =
                flatbuffers::root::<DirectoryEntryMetadata>(&bytes).unwrap();
            assert_eq!(fb_data.size(), 15); // "updated content"
            assert_ne!(fb_data.size(), original_size);
        }

        #[tokio::test]
        async fn test_cache_performance_improvement() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            // Create a directory with many files to make operations slower
            let large_dir = temp_dir.join("large_dir");
            fs::create_dir(&large_dir).unwrap();
            for i in 0..100 {
                File::create(large_dir.join(format!("file_{i:03}.txt")))
                    .unwrap()
                    .write_all(format!("content {i}").as_bytes())
                    .unwrap();
            }

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            // Time the first request (cache miss)
            let start = Instant::now();
            let req = Request::builder()
                .uri("/get_dir_info?path=large_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            let first_request_time = start.elapsed();
            assert_eq!(resp.status(), http::StatusCode::OK);

            // Time the second request (cache hit)
            let start = Instant::now();
            let req = Request::builder()
                .uri("/get_dir_info?path=large_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let second_request_time = start.elapsed();
            assert_eq!(resp.status(), http::StatusCode::OK);

            // Cache hit should be faster
            assert!(
                second_request_time < first_request_time,
                "Cache hit ({second_request_time:?}) should be at faster than miss ({first_request_time:?})"
            );
        }

        #[tokio::test]
        async fn test_cache_consistency_across_requests() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            // Make multiple requests and ensure they return consistent data
            let mut responses = Vec::new();
            for _ in 0..5 {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();
                let resp = app.clone().oneshot(req).await.unwrap();
                assert_eq!(resp.status(), http::StatusCode::OK);

                let bytes = resp.collect().await.unwrap().to_bytes();
                responses.push(bytes);
            }

            // All responses should be identical
            let first_response = &responses[0];
            for (i, response) in responses.iter().enumerate().skip(1) {
                assert_eq!(
                    response, first_response,
                    "Response {i} differs from first response"
                );
            }
        }

        #[cfg(feature = "stats")]
        #[tokio::test]
        async fn test_cache_stats_accuracy() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

            // Create multiple test directories
            for i in 1..=3 {
                fs::create_dir(temp_dir.join(format!("stats_test_{i}"))).unwrap();
            }

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            // Make requests in a predictable pattern
            let test_pattern = [
                ("stats_test_1", false), // miss
                ("stats_test_2", false), // miss
                ("stats_test_1", true),  // hit
                ("stats_test_3", false), // miss
                ("stats_test_2", true),  // hit
                ("stats_test_1", true),  // hit
            ];

            for (i, (path, expected_hit)) in test_pattern.iter().enumerate() {
                let req = Request::builder()
                    .uri(format!("/get_dir_info?path={path}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();
                let resp = app.clone().oneshot(req).await.unwrap();
                assert_eq!(resp.status(), http::StatusCode::OK);

                let (hits, misses) = state.cache_stats.get();
                if *expected_hit {
                    assert!(
                        hits > 0,
                        "Expected cache hit for request {} ({path}), but hits = {hits}",
                        i + 1
                    );
                }

                // Total operations should match request count
                assert_eq!(
                    hits + misses,
                    (i + 1) as u64,
                    "Total cache operations should equal request count at step {}",
                    i + 1
                );
            }

            // Final verification
            let (final_hits, final_misses) = state.cache_stats.get();
            assert_eq!(final_hits, 3, "Should have exactly 3 cache hits");
            assert_eq!(final_misses, 3, "Should have exactly 3 cache misses");
            assert_eq!(final_hits + final_misses, test_pattern.len() as u64);
        }
    }
    mod security {
        use super::*;

        #[tokio::test]
        async fn test_path_traversal_protection_posix() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let mut app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            {
                let req = Request::builder()
                    .uri("/get_dir_entry_info?path=../passwd.txt")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_entry_info?path=/../passwd.txt")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_entry_info?path=test_dir/../../passwd.txt")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir/../")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir/../../")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=./test_dir/../")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=./test_dir/../../")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir/./../")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir/./../../")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }
        }

        #[tokio::test]
        async fn test_path_traversal_protection_windows() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            let mut app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            {
                let req = Request::builder()
                    .uri("/get_dir_entry_info?path=..\\passwd.txt")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_entry_info?path=\\..\\passwd.txt")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_entry_info?path=test_dir\\..\\..\\passwd.txt")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir\\..\\")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir\\..\\..\\")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=.\\test_dir\\..\\")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=.\\test_dir\\..\\..\\")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir\\.\\..\\")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
            }

            {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir\\.\\..\\..\\")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            }
        }

        /// The traversal tests above all send a literal `../` in the URI.
        /// That is not the only way one arrives: the query value is
        /// percent-decoded (`extract_path`) *before* it reaches the
        /// normaliser (`utils::path::normalize`), so a client can encode the
        /// same attempt as `%2e%2e%2f` and it must be rejected only after
        /// decoding turns it back into `..` - decoding happens first, then
        /// normalisation, and both steps have to actually run for this to be
        /// safe. This is the seam between the two, exercised end-to-end
        /// through the real router rather than assumed from each piece's own
        /// unit tests passing in isolation.
        #[tokio::test]
        async fn test_path_traversal_protection_percent_encoded() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);

            let mut app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            // Every segment encoded.
            for uri in [
                "/get_dir_entry_info?path=%2e%2e%2fpasswd.txt",
                "/get_dir_entry_info?path=%2e%2e/passwd.txt",
                "/get_dir_entry_info?path=test_dir%2f..%2f..%2fpasswd.txt",
                "/get_dir_entry_info?path=test_dir/%2e%2e/%2e%2e/passwd.txt",
                // Uppercase hex digits are just as legal as lowercase.
                "/get_dir_entry_info?path=%2E%2E%2Fpasswd.txt",
            ] {
                let req = Request::builder()
                    .uri(uri)
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(
                    resp.status(),
                    http::StatusCode::FORBIDDEN,
                    "should have been rejected: {uri}"
                );
            }

            // A benign request that only *looks* suspicious pre-decode must
            // still work - encoding is not itself a reason to reject.
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=test_dir%2ffile_in_dir.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        /// A raw NUL byte can only arrive via percent-encoding - `%00` is
        /// syntactically legal inside a URI, so `http::Uri` parses it, and it
        /// only becomes a real `\0` once `extract_path` decodes the value.
        /// `Path::join`/`canonicalize` behave in ways that are not obviously
        /// safe with an embedded NUL (a C-level API boundary reads to the
        /// first NUL), so `utils::path::normalize` rejects it outright rather
        /// than letting the OS decide.
        #[tokio::test]
        async fn test_embedded_nul_byte_is_rejected() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);

            let mut app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state);

            for uri in [
                "/get_dir_entry_info?path=test_file.txt%00.png",
                "/get_dir_entry_info?path=%00",
            ] {
                let req = Request::builder()
                    .uri(uri)
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();

                let resp = app.call(req).await.unwrap();

                assert_eq!(
                    resp.status(),
                    http::StatusCode::FORBIDDEN,
                    "should have been rejected: {uri}"
                );
            }
        }

        /// A classically dangerous decoder bug: interpreting an *overlong*
        /// UTF-8 encoding of `/` or `.` (e.g. the old IIS `%c0%af` issue) as
        /// the ASCII character instead of rejecting it outright. Rust's UTF-8
        /// validation has no such leniency - an overlong sequence is not
        /// valid UTF-8 at all - but this is exactly the kind of assumption
        /// worth proving against the actual decoder rather than trusting the
        /// dependency's changelog.
        #[tokio::test]
        async fn test_overlong_utf8_encoding_is_rejected_not_reinterpreted() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);

            let app = Router::new()
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state);

            // %c0%af is the overlong two-byte encoding of '/' (0x2F).
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=..%c0%afpasswd.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            // Must not be treated as a slash and used to traverse; rejected
            // as malformed input is the only acceptable outcome here.
            assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        #[cfg(unix)]
        async fn test_permission_denied() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);
            let restricted_dir = temp_dir.join("restricted");
            fs::create_dir(&restricted_dir).unwrap();
            let restricted_file = restricted_dir.join("no_access.txt");
            File::create(&restricted_file).unwrap();

            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o000)).unwrap();
            }

            // Root (or anything holding CAP_DAC_OVERRIDE) reads a mode-000
            // directory regardless, so there is no denial to observe.
            // Containers typically run tests as root; the test can say
            // nothing there, rather than fail on the setup.
            if fs::read_dir(&restricted_dir).is_ok() {
                fs::set_permissions(
                    &restricted_dir,
                    <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
                )
                .unwrap();
                eprintln!(
                    "test_permission_denied: permissions are not enforced for this user (root?); nothing to test"
                );
                return;
            }

            let app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/get_dir_info?path=restricted")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

            fs::set_permissions(
                restricted_dir,
                <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
            )
            .unwrap();
        }

        #[tokio::test]
        async fn test_symlink_handling() {
            let temp = tempfile::tempdir().unwrap();

            let temp_dir = temp.path();

            let state = setup_test_env(temp_dir);

            // Create test file and valid symlink within base directory
            let target_path = temp_dir.join("target_file.txt");
            File::create(&target_path)
                .unwrap()
                .write_all(b"valid content")
                .unwrap();

            let valid_symlink = temp_dir.join("valid_link.txt");
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target_path, &valid_symlink).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&target_path, &valid_symlink).unwrap();

            // Create malicious symlink pointing outside base directory
            let outside_path = temp_dir.parent().unwrap().join("secret.txt");
            File::create(&outside_path)
                .unwrap()
                .write_all(b"protected")
                .unwrap();

            let malicious_symlink = temp_dir.join("malicious_link.txt");
            #[cfg(unix)]
            std::os::unix::fs::symlink("../secret.txt", &malicious_symlink).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_file("..\\secret.txt", &malicious_symlink).unwrap();

            let mut app = Router::new()
                .route("/get_file", axum::routing::get(get_file_handler))
                .route(
                    "/get_dir_entry_info",
                    axum::routing::get(get_dir_entry_info_handler),
                )
                .with_state(state);

            // Test valid symlink
            let req = Request::builder()
                .uri("/get_file?path=valid_link.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);
            let bytes = resp.collect().await.unwrap().to_bytes();
            assert_eq!(bytes, "valid content");

            // Test malicious symlink
            let req = Request::builder()
                .uri("/get_file?path=malicious_link.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

            // Test valid symlink
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=valid_link.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            // Test malicious symlink
            let req = Request::builder()
                .uri("/get_dir_entry_info?path=malicious_link.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }
    }

    /// `handle_fs_events` is a pure function of `(events, store)`: everything
    /// upstream of it - the OS's inotify/FSEvents/ReadDirectoryChangesW backend,
    /// `notify`'s debouncing - is inherently timing-dependent and outside this
    /// crate. Testing invalidation *through* a real watcher means asserting on
    /// wall-clock behaviour of a background thread, which is exactly the kind
    /// of test that passes locally and flakes in CI.
    ///
    /// So these construct `DebouncedEvent`s directly and call the handler
    /// in-process. No sleeping, no polling, no background thread, no thread
    /// pool sized to the number of watchers under test - each case is a
    /// function call and an assertion, and either it invalidates the right
    /// thing or it does not.
    mod file_watcher {
        use super::*;
        use notify_debouncer_full::DebouncedEvent;
        use notify_debouncer_full::notify::event::{
            CreateKind, DataChange, Flag, MetadataKind, ModifyKind, RemoveKind, RenameMode,
        };
        use notify_debouncer_full::notify::{Event, EventKind};

        fn event(kind: EventKind, paths: &[&std::path::Path]) -> DebouncedEvent {
            let event = paths
                .iter()
                .fold(Event::new(kind), |event, path| event.add_path(path.to_path_buf()));

            DebouncedEvent::new(event, std::time::Instant::now())
        }

        /// A directory whose listing is primed in the cache, ready to assert
        /// on after feeding the handler an event.
        async fn primed(state: &AppState, relative: &str) -> std::path::PathBuf {
            state.store.directory_listing(relative).await.unwrap();
            canonical(state, relative)
        }

        #[tokio::test]
        async fn create_invalidates_the_parent_listing() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;

            let new_file = state.store.base().join("new_file.txt");
            let events = [event(EventKind::Create(CreateKind::File), &[&new_file])];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(!state.store.has_directory(&root));
        }

        #[tokio::test]
        async fn data_modification_invalidates_content_and_parent_listing() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;

            let (target, content, _, _) = state.store.file_content("test_file.txt").await.unwrap();
            assert!(matches!(content, utils::cache::Content::Resident(_)));
            assert!(state.store.has_content(&target));

            let events = [event(
                EventKind::Modify(ModifyKind::Data(DataChange::Any)),
                &[&target],
            )];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(
                !state.store.has_content(&target),
                "modified file's cached bytes should be dropped"
            );
            assert!(
                !state.store.has_directory(&root),
                "parent listing quotes the file's size, so it must go too"
            );
        }

        #[tokio::test]
        async fn metadata_modification_invalidates_content_and_parent_listing() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;

            let (target, _, _, _) = state.store.file_content("test_file.txt").await.unwrap();

            let events = [event(
                EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
                &[&target],
            )];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(!state.store.has_content(&target));
            assert!(!state.store.has_directory(&root));
        }

        #[tokio::test]
        async fn removing_a_file_invalidates_it_and_the_parent_listing() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;

            let (target, _, _, _) = state.store.file_content("test_file.txt").await.unwrap();
            assert!(state.store.has_content(&target));

            let events = [event(
                EventKind::Remove(RemoveKind::File),
                &[&target],
            )];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(!state.store.has_content(&target));
            assert!(!state.store.has_directory(&root));
        }

        #[tokio::test]
        async fn removing_a_directory_invalidates_its_whole_subtree() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;
            let sub_dir = primed(&state, "test_dir").await;
            let nested = primed(&state, "test_dir/nested_test_dir").await;

            let files = [
                "test_dir/file_in_dir.txt",
                "test_dir/nested_test_dir/file_in_nested_test_dir.txt",
            ];
            let mut cached_paths = Vec::new();
            for file in files {
                let (path, _, _, _) = state.store.file_content(file).await.unwrap();
                assert!(state.store.has_content(&path));
                cached_paths.push(path);
            }
            fs::rename(temp.path().join("test_dir"), temp.path().join("old_dir")).unwrap();
            fs::create_dir_all(temp.path().join("test_dir/nested_test_dir")).unwrap();
            for file in files {
                fs::write(temp.path().join(file), b"replacement bytes").unwrap();
            }

            let events = [event(EventKind::Remove(RemoveKind::Folder), &[&sub_dir])];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(
                !state.store.has_directory(&root),
                "parent listing named the removed directory, so it must go too"
            );
            assert!(!state.store.has_directory(&sub_dir));
            assert!(
                !state.store.has_directory(&nested),
                "a descendant of the removed directory must not survive as a stale entry"
            );
            let app = crate::build_router(Arc::clone(&state));
            for (file, path) in files.into_iter().zip(cached_paths) {
                assert!(!state.store.has_content(&path));
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!("/get_file?path={file}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    "replacement bytes"
                );
            }
        }

        #[tokio::test]
        async fn rename_invalidates_both_endpoints() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;

            let from = state.store.base().join("test_file.txt");
            let to = state.store.base().join("renamed.txt");

            // `notify` reports a completed rename as one event carrying both
            // paths - source first, destination last.
            let events = [event(
                EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                &[&from, &to],
            )];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(!state.store.has_directory(&root));
        }

        #[tokio::test]
        async fn a_rescan_flag_drops_every_cache_regardless_of_other_events() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());

            let root = primed(&state, "").await;
            let sub_dir = primed(&state, "test_dir").await;
            let (target, _, _, _) = state.store.file_content("test_file.txt").await.unwrap();

            let mut rescan = Event::new(EventKind::Other);
            rescan = rescan.set_flag(Flag::Rescan);

            // A harmless-looking create sits after the rescan in the same
            // batch; `need_rescan` must short-circuit before it is examined,
            // since after a rescan every path is suspect, not just this one.
            let unrelated = state.store.base().join("after_rescan.txt");
            let events = [
                DebouncedEvent::new(rescan, std::time::Instant::now()),
                event(EventKind::Create(CreateKind::File), &[&unrelated]),
            ];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(!state.store.has_directory(&root));
            assert!(!state.store.has_directory(&sub_dir));
            assert!(!state.store.has_content(&target));
        }

        #[tokio::test]
        async fn create_invalidates_the_grandparent_listing() {
            // The create changed the parent's times, which the grandparent's
            // listing quotes.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;
            let sub_dir = primed(&state, "test_dir").await;

            let new_file = sub_dir.join("new_file.txt");
            let events = [event(EventKind::Create(CreateKind::File), &[&new_file])];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(!state.store.has_directory(&sub_dir));
            assert!(!state.store.has_directory(&root));
        }

        #[tokio::test]
        async fn metadata_modification_of_the_root_invalidates_its_own_listing() {
            // The root has no parent listing to quote its times; its own node
            // answers for them.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;

            let events = [event(
                EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
                &[&root],
            )];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(!state.store.has_directory(&root));
        }

        #[tokio::test]
        async fn a_modification_of_unknown_kind_leaves_the_subtree_in_place() {
            // Windows reports an in-place write as `Modify(Any)`, which must
            // not cost every cached entry beneath the path.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;
            let sub_dir = primed(&state, "test_dir").await;
            let nested = primed(&state, "test_dir/nested_test_dir").await;

            for kind in [ModifyKind::Any, ModifyKind::Other] {
                let events = [event(EventKind::Modify(kind), &[&sub_dir])];

                utils::cache::handle_fs_events(&events, &state.store).await;
            }

            assert!(!state.store.has_directory(&root));
            assert!(state.store.has_directory(&nested));
        }

        #[tokio::test]
        async fn unrelated_event_kinds_do_not_invalidate_anything() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let root = primed(&state, "").await;

            let touched = state.store.base().join("test_file.txt");
            let events = [event(
                EventKind::Access(notify_debouncer_full::notify::event::AccessKind::Read),
                &[&touched],
            )];

            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(
                state.store.has_directory(&root),
                "a plain access should not evict anything"
            );
        }
    }

    /// The change feed, end to end through the router, and the coherence rule
    /// it rests on: an answer the feed cannot vouch for goes out `no-store`.
    ///
    /// Events are fed to `handle_fs_events` directly, for the reason the
    /// `file_watcher` tests give; what is under test is what a client polling
    /// `/get_changes` is told, and what the metadata routes mark.
    mod change_feed {
        use super::*;
        use generated::blorg_meta_flat::ChangeBatch;
        use notify_debouncer_full::DebouncedEvent;
        use notify_debouncer_full::notify::event::{
            CreateKind, DataChange, Flag, ModifyKind, RemoveKind, RenameMode,
        };
        use notify_debouncer_full::notify::{Event, EventKind};

        #[derive(Debug, PartialEq, Eq)]
        struct Batch {
            epoch: u64,
            generation: u64,
            reset: bool,
            modified: Vec<String>,
            created: Vec<String>,
            removed: Vec<String>,
        }

        fn event(kind: EventKind, paths: &[&std::path::Path]) -> DebouncedEvent {
            let event = paths
                .iter()
                .fold(Event::new(kind), |event, path| event.add_path(path.to_path_buf()));

            DebouncedEvent::new(event, std::time::Instant::now())
        }

        fn modified(state: &AppState, relative: &str) -> DebouncedEvent {
            event(
                EventKind::Modify(ModifyKind::Data(DataChange::Content)),
                &[&canonical(state, relative)],
            )
        }

        fn created(state: &AppState, relative: &str) -> DebouncedEvent {
            fs::create_dir(canonical(state, relative)).unwrap();

            event(
                EventKind::Create(CreateKind::Folder),
                &[&canonical(state, relative)],
            )
        }

        fn renamed(state: &AppState, from: &str, to: &str) -> DebouncedEvent {
            fs::rename(canonical(state, from), canonical(state, to)).unwrap();

            event(
                EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                &[&canonical(state, from), &canonical(state, to)],
            )
        }

        fn removed(state: &AppState, relative: &str) -> DebouncedEvent {
            fs::remove_file(canonical(state, relative)).unwrap();

            event(
                EventKind::Remove(RemoveKind::File),
                &[&canonical(state, relative)],
            )
        }

        fn live(config: utils::cache::Config) -> (tempfile::TempDir, Arc<AppState>) {
            let temp = tempfile::tempdir().unwrap();
            fs::create_dir(temp.path().join("test_dir")).unwrap();
            fs::create_dir(temp.path().join("other_test_dir")).unwrap();
            File::create(temp.path().join("test_dir/file_in_dir.txt"))
                .unwrap()
                .write_all(b"nested content")
                .unwrap();

            let state = state_with_config(temp.path(), config);
            state.store.feed().go_live();

            (temp, state)
        }

        async fn get(state: &Arc<AppState>, uri: &str) -> axum::response::Response {
            build_router(state.clone())
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap()
        }

        fn no_store(response: &axum::response::Response) -> bool {
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .is_some_and(|value| value == "no-store")
        }

        async fn poll(state: &Arc<AppState>, epoch: u64, since: u64) -> Batch {
            let response = get(state, &format!("/get_changes?epoch={epoch}&since={since}")).await;
            assert_eq!(response.status(), http::StatusCode::OK);

            let bytes = response.collect().await.unwrap().to_bytes();
            let batch = flatbuffers::root::<ChangeBatch>(&bytes).unwrap();
            let strings = |paths: Option<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<&str>>>| {
                let mut paths: Vec<String> =
                    paths.unwrap().iter().map(str::to_owned).collect();
                paths.sort();
                paths
            };

            Batch {
                epoch: batch.epoch(),
                generation: batch.generation(),
                reset: batch.reset(),
                modified: strings(batch.modified()),
                created: strings(batch.created()),
                removed: strings(batch.removed()),
            }
        }

        #[tokio::test]
        async fn refuses_to_answer_until_the_watcher_is_live() {
            // An empty batch would tell the client nothing changed, which is a
            // promise only a running watcher can make.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());

            let response = get(&state, "/get_changes").await;
            assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        }

        #[tokio::test]
        async fn a_new_client_is_told_to_reset_at_the_current_generation() {
            let (_temp, state) = live(utils::cache::Config::default());

            let batch = poll(&state, 0, 0).await;

            assert!(batch.reset);
            assert_eq!(batch.epoch, state.store.feed().epoch());
            assert_eq!(batch.generation, 0);
        }

        #[tokio::test]
        async fn a_batch_names_what_changed_the_way_a_client_asked_for_it() {
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let events = [
                modified(&state, "test_dir/file_in_dir.txt"),
                created(&state, "test_dir/new_dir"),
            ];
            utils::cache::handle_fs_events(&events, &state.store).await;

            assert_eq!(
                poll(&state, epoch, 0).await,
                Batch {
                    epoch,
                    generation: 1,
                    reset: false,
                    modified: vec!["test_dir/file_in_dir.txt".to_owned()],
                    created: vec!["test_dir/new_dir".to_owned()],
                    removed: Vec::new(),
                }
            );
        }

        #[tokio::test]
        async fn a_rename_reports_its_old_path_removed_and_its_new_one_created() {
            // The client keys everything by path, so a rename is two facts to
            // it: the old name no longer resolves, and the new one now does.
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let events = [renamed(&state, "test_dir", "moved_dir")];
            utils::cache::handle_fs_events(&events, &state.store).await;

            let batch = poll(&state, epoch, 0).await;
            assert_eq!(batch.modified, Vec::<String>::new());
            assert_eq!(batch.created, vec!["moved_dir".to_owned()]);
            assert_eq!(batch.removed, vec!["test_dir".to_owned()]);
        }

        #[tokio::test]
        async fn a_change_of_existence_outranks_a_later_modification() {
            // A client that missed the create still has to hear that the path
            // now exists, even when a write to it came after; reporting only
            // the write would leave its cached "not found" in place.
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let events = [created(&state, "test_dir/new_dir")];
            utils::cache::handle_fs_events(&events, &state.store).await;
            let events = [modified(&state, "test_dir/new_dir")];
            utils::cache::handle_fs_events(&events, &state.store).await;

            let batch = poll(&state, epoch, 0).await;
            assert_eq!(batch.generation, 2);
            assert_eq!(batch.modified, Vec::<String>::new());
            assert_eq!(batch.created, vec!["test_dir/new_dir".to_owned()]);

            let since_the_create = poll(&state, epoch, 1).await;
            assert_eq!(since_the_create.modified, vec!["test_dir/new_dir".to_owned()]);
            assert_eq!(since_the_create.created, Vec::<String>::new());
        }

        #[tokio::test]
        async fn a_removal_is_reported_as_one() {
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let events = [removed(&state, "test_dir/file_in_dir.txt")];
            utils::cache::handle_fs_events(&events, &state.store).await;

            let batch = poll(&state, epoch, 0).await;
            assert!(batch.modified.is_empty() && batch.created.is_empty());
            assert_eq!(batch.removed, vec!["test_dir/file_in_dir.txt".to_owned()]);
        }

        #[tokio::test]
        async fn a_path_changed_in_several_generations_is_sent_once() {
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            for _ in 0..3 {
                let events = [modified(&state, "test_dir/file_in_dir.txt")];
                utils::cache::handle_fs_events(&events, &state.store).await;
            }

            let batch = poll(&state, epoch, 0).await;

            assert_eq!(batch.generation, 3);
            assert_eq!(batch.modified, vec!["test_dir/file_in_dir.txt".to_owned()]);
        }

        #[tokio::test]
        async fn a_client_that_is_up_to_date_is_held_until_something_changes() {
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let waiting = tokio::spawn({
                let state = state.clone();
                async move { poll(&state, epoch, 0).await }
            });

            // Give the poll time to start waiting; if it answered early it
            // would have an empty batch, which the assertion below rejects.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let events = [modified(&state, "test_dir/file_in_dir.txt")];
            utils::cache::handle_fs_events(&events, &state.store).await;

            let batch = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
                .await
                .expect("the held poll should be answered by the change, not the hold")
                .unwrap();

            assert_eq!(batch.generation, 1);
            assert_eq!(batch.modified, vec!["test_dir/file_in_dir.txt".to_owned()]);
        }

        #[tokio::test]
        async fn the_heartbeat_is_an_empty_batch_at_the_same_generation() {
            let (_temp, state) = live(utils::cache::Config {
                feed_hold: std::time::Duration::from_millis(20),
                ..utils::cache::Config::default()
            });
            let epoch = state.store.feed().epoch();

            let batch = poll(&state, epoch, 0).await;

            assert!(!batch.reset);
            assert_eq!(batch.generation, 0);
            assert!(batch.modified.is_empty() && batch.created.is_empty() && batch.removed.is_empty());
        }

        #[tokio::test]
        async fn a_client_behind_what_is_retained_is_told_to_reset() {
            let (_temp, state) = live(utils::cache::Config {
                feed_retained: 1,
                ..utils::cache::Config::default()
            });
            let epoch = state.store.feed().epoch();

            for relative in ["test_dir", "other_test_dir"] {
                let events = [modified(&state, relative)];
                utils::cache::handle_fs_events(&events, &state.store).await;
            }

            assert!(poll(&state, epoch, 0).await.reset);

            let caught_up = poll(&state, epoch, 1).await;
            assert!(!caught_up.reset);
            assert_eq!(caught_up.modified, vec!["other_test_dir".to_owned()]);
        }

        #[tokio::test]
        async fn another_epoch_is_told_to_reset() {
            // A restarted server numbers generations from zero again, so a
            // client's generation from the previous process means nothing.
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            assert!(poll(&state, epoch ^ 2, 0).await.reset);
        }

        #[tokio::test]
        async fn a_rescan_resets_every_client() {
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let rescan = Event::new(EventKind::Other).set_flag(Flag::Rescan);
            let events = vec![DebouncedEvent::new(rescan, std::time::Instant::now())];
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(Ok(events)).await.unwrap();
            drop(tx);
            receive_fs_events(rx, &state).await;

            let batch = poll(&state, epoch, 0).await;
            assert!(batch.reset);
            assert_eq!(batch.generation, 1);
        }

        // Send through the production receiver after warming all tiers. A feed
        // failure alone says nothing about the HTTP bytes still served from cache.
        #[tokio::test]
        async fn a_watcher_failure_drops_cached_answers_and_stops_the_feed() {
            let (temp, state) = live(utils::cache::Config::default());
            let file_uri = "/get_file?path=test_dir/file_in_dir.txt";
            let listing_uri = "/get_dir_info?path=test_dir";
            let metadata_uri = "/get_dir_entry_info?path=test_dir/file_in_dir.txt";

            for uri in [file_uri, listing_uri, metadata_uri] {
                let response = get(&state, uri).await;
                assert_eq!(response.status(), http::StatusCode::OK);
                let _ = response.collect().await.unwrap();
            }
            assert!(
                state
                    .store
                    .has_content(&canonical(&state, "test_dir/file_in_dir.txt"))
            );
            assert!(state.store.has_directory(&canonical(&state, "test_dir")));

            fs::rename(temp.path().join("test_dir"), temp.path().join("old_dir")).unwrap();
            fs::create_dir(temp.path().join("test_dir")).unwrap();
            fs::write(temp.path().join("test_dir/file_in_dir.txt"), b"replacement").unwrap();
            fs::write(temp.path().join("test_dir/new.txt"), b"new").unwrap();

            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(Err(vec![notify_debouncer_full::notify::Error::generic(
                "lost events",
            )]))
            .await
            .unwrap();
            drop(tx);
            receive_fs_events(rx, &state).await;

            let response = get(&state, file_uri).await;
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(response.collect().await.unwrap().to_bytes(), "replacement");

            let response = get(&state, listing_uri).await;
            assert_eq!(response.status(), http::StatusCode::OK);
            let bytes = response.collect().await.unwrap().to_bytes();
            let listing = flatbuffers::root::<Directory>(&bytes).unwrap();
            let mut names: Vec<_> = listing
                .files()
                .unwrap()
                .iter()
                .map(|entry| entry.name().unwrap())
                .collect();
            names.sort_unstable();
            assert_eq!(names, ["file_in_dir.txt", "new.txt"]);

            let response = get(&state, metadata_uri).await;
            assert_eq!(response.status(), http::StatusCode::OK);
            let bytes = response.collect().await.unwrap().to_bytes();
            assert_eq!(
                flatbuffers::root::<DirectoryEntryMetadata>(&bytes)
                    .unwrap()
                    .size(),
                11
            );

            let response = get(&state, "/get_changes").await;
            assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        }

        #[tokio::test]
        async fn a_modification_of_unknown_kind_is_reported_as_modified() {
            // What Windows reports for an in-place write.
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let events = [event(
                EventKind::Modify(ModifyKind::Any),
                &[&canonical(&state, "test_dir/file_in_dir.txt")],
            )];
            utils::cache::handle_fs_events(&events, &state.store).await;

            let batch = poll(&state, epoch, 0).await;
            assert_eq!(batch.modified, vec!["test_dir/file_in_dir.txt".to_owned()]);
            assert!(batch.created.is_empty() && batch.removed.is_empty());
        }

        #[tokio::test]
        async fn a_path_repeated_in_one_batch_takes_one_retained_slot() {
            let (_temp, state) = live(utils::cache::Config {
                feed_retained: 1,
                ..utils::cache::Config::default()
            });
            let epoch = state.store.feed().epoch();

            let events = [
                created(&state, "test_dir/new_dir"),
                event(
                    EventKind::Modify(ModifyKind::Name(RenameMode::To)),
                    &[&canonical(&state, "test_dir/new_dir")],
                ),
            ];
            utils::cache::handle_fs_events(&events, &state.store).await;

            let batch = poll(&state, epoch, 0).await;
            assert!(!batch.reset);
            assert_eq!(batch.created, vec!["test_dir/new_dir".to_owned()]);
        }

        #[tokio::test]
        async fn a_batch_naming_a_path_outside_the_root_is_a_reset() {
            // No client could have asked for it by a key, so the batch cannot
            // be reported precisely.
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();
            let outside = tempfile::tempdir().unwrap();

            let events = [
                modified(&state, "test_dir/file_in_dir.txt"),
                event(
                    EventKind::Modify(ModifyKind::Data(DataChange::Content)),
                    &[&outside.path().join("elsewhere.txt")],
                ),
            ];
            utils::cache::handle_fs_events(&events, &state.store).await;

            let batch = poll(&state, epoch, 0).await;
            assert!(batch.reset);
            assert_eq!(batch.generation, 1);
        }

        #[tokio::test]
        async fn a_held_poll_is_refused_when_the_watcher_fails() {
            let (_temp, state) = live(utils::cache::Config::default());
            let epoch = state.store.feed().epoch();

            let waiting = tokio::spawn({
                let state = state.clone();
                async move { get(&state, &format!("/get_changes?epoch={epoch}&since=0")).await }
            });

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            state.store.feed().fail();

            let response = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
                .await
                .expect("the held poll should be answered by the failure, not the hold")
                .unwrap();

            assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        }

        #[tokio::test]
        async fn going_live_drops_what_was_loaded_before_the_watch() {
            // No event will report a change made before the watch was in
            // place, so nothing loaded by then may be vouched for after.
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());
            let epoch = state.store.feed().epoch();
            let directory = canonical(&state, "test_dir");

            state.store.directory_listing("test_dir").await.unwrap();
            assert!(state.store.has_directory(&directory));

            state.store.go_live();

            assert!(!state.store.has_directory(&directory));

            let batch = poll(&state, epoch, 0).await;
            assert!(batch.reset);
            assert_eq!(batch.generation, 1);

            // A load that began before going live is overtaken.
            state.store.plant_directory(&directory, 0).await;
            assert!(no_store(&get(&state, "/get_dir_info?path=test_dir").await));
        }

        #[cfg(not(windows))]
        #[tokio::test]
        async fn the_watcher_takes_the_feed_live_once_it_is_watching() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env(temp.path());

            start_fs_watcher(state.store.base().to_path_buf(), state.clone());

            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !state.store.feed().is_live() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the feed should go live once the watch is in place");
        }

        #[tokio::test]
        async fn a_load_overtaken_by_a_generation_is_served_once_and_not_kept() {
            // Without the stamp, this entry - read before the change, cached
            // after its invalidation - would be served as current until its
            // TTL, and a client that had already applied the change would keep
            // it for good.
            let (_temp, state) = live(utils::cache::Config::default());
            let directory = canonical(&state, "test_dir");

            state.store.plant_directory(&directory, 0).await;
            state.store.feed().begin();

            let response = get(&state, "/get_dir_info?path=test_dir").await;
            assert_eq!(response.status(), http::StatusCode::OK);
            assert!(no_store(&response));
            assert!(!state.store.has_directory(&directory));

            let reloaded = get(&state, "/get_dir_info?path=test_dir").await;
            assert!(!no_store(&reloaded));
            assert!(state.store.has_directory(&directory));
        }

        #[tokio::test]
        async fn a_vouched_entry_outlives_a_generation_that_did_not_touch_it() {
            // The stamp must not cost the cache its point: only a load a
            // generation overtook is distrusted, not every entry older than
            // the newest generation.
            let (_temp, state) = live(utils::cache::Config::default());
            let directory = canonical(&state, "test_dir");

            assert!(!no_store(&get(&state, "/get_dir_info?path=test_dir").await));

            let events = [modified(&state, "other_test_dir")];
            utils::cache::handle_fs_events(&events, &state.store).await;

            assert!(state.store.has_directory(&directory));
            assert!(!no_store(&get(&state, "/get_dir_info?path=test_dir").await));
            assert!(!no_store(&get(&state, "/get_dir_entry_info?path=test_dir/file_in_dir.txt").await));
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn an_answer_reached_through_a_symlink_is_never_vouched_for() {
            // The watcher names the target; a client caching under the link's
            // name would never hear about it.
            let (temp, state) = live(utils::cache::Config::default());
            std::os::unix::fs::symlink(temp.path().join("test_dir"), temp.path().join("alias"))
                .unwrap();

            assert!(no_store(&get(&state, "/get_dir_info?path=alias").await));
            assert!(no_store(&get(&state, "/get_dir_entry_info?path=alias/file_in_dir.txt").await));
            assert!(no_store(&get(&state, "/get_file?path=alias/file_in_dir.txt").await));
            assert!(!no_store(&get(&state, "/get_dir_info?path=test_dir").await));
        }
    }
}
