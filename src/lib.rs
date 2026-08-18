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

/// Pulls `path` straight out of the query string, bypassing
/// `axum::extract::Query`'s `serde`-deserialise pipeline - a derive-generated
/// visitor, field-name matching, and an unconditional `String` allocation for
/// the value, none of which a single required field needs. Borrows from `uri`
/// whenever the value has no percent-escapes, which is the common case.
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
) -> Result<bytes::Bytes, AppError> {
    let path = extract_path(&uri)?;
    log_debug!("[FILE INFO] Handling request for: {path}");

    let (encoded, origin) = data.store.entry_metadata(&path).await?;
    data.cache_stats.record(origin);

    Ok(encoded)
}

/// `GET /get_dir_info` - the serialised listing for a directory.
///
/// # Errors
///
/// Traversal, missing path, or an unreadable directory.
pub async fn get_dir_info_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    uri: axum::http::Uri,
) -> Result<bytes::Bytes, AppError> {
    let path = extract_path(&uri)?;
    log_debug!("[DIR INFO] Handling request for: {path}");

    let (encoded, origin) = data.store.directory_listing(&path).await?;
    data.cache_stats.record(origin);

    Ok(encoded)
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

    let (canonical, content, origin) = data.store.file_content(&path).await?;
    data.cache_stats.record(origin);

    match content {
        // Answered entirely from memory: no open, no read, no page-cache round
        // trip, and the body is a slice of a buffer we already hold.
        utils::cache::Content::Resident(node) => Ok(utils::http::resident_response(
            &node,
            request.method(),
            request.headers(),
        )),

        // Too large to hold resident, so hand it to the streaming file service.
        utils::cache::Content::Streamed => {
            use axum::response::IntoResponse as _;

            Ok(tower_http::services::ServeFile::new(&canonical)
                .try_call(request)
                .await?
                .into_response())
        }
    }
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

/// `path` must be the canonical root: `notify` builds event paths by joining
/// the watched root with the on-disk name, so watching the canonical form is
/// what makes event paths line up with the cache keys they invalidate.
pub fn start_fs_watcher(path: std::path::PathBuf, state: std::sync::Arc<AppState>) {
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);

        let mut debouncer = notify_debouncer_full::new_debouncer(
            tokio::time::Duration::from_secs(2),
            None,
            move |res| {
                if let Err(e) = tx.blocking_send(res) {
                    log_error_with_context!(e, "watch send error");
                }
            },
        )?;

        debouncer.watch(
            &path,
            notify_debouncer_full::notify::RecursiveMode::Recursive,
        )?;

        while let Some(res) = rx.recv().await {
            match res {
                Ok(events) => utils::cache::handle_fs_events(&events, &state.store).await,
                Err(e) => {
                    log_error_with_context!(e, "watch receive error");
                }
            }
        }

        Ok::<(), notify_debouncer_full::notify::Error>(())
    });
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

            let (target, content, _) = state.store.file_content("test_file.txt").await.unwrap();
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

            let (target, _, _) = state.store.file_content("test_file.txt").await.unwrap();

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

            let (target, _, _) = state.store.file_content("test_file.txt").await.unwrap();
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

            let events = [event(
                EventKind::Remove(RemoveKind::Folder),
                &[&sub_dir],
            )];

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
            let (target, _, _) = state.store.file_content("test_file.txt").await.unwrap();

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
}
