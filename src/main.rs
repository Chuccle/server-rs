#![deny(clippy::all)]

mod generated {
    #![allow(clippy::all, unused_imports, dead_code, unsafe_op_in_unsafe_fn)]
    include!(concat!(
        env!("OUT_DIR"),
        "/metadata_flatbuffer_generated.rs"
    ));
}
mod utils;

// TODO:
// File serving caching/chunking

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Path traversal attempt detected")]
    PathTraversal,
    #[error("Invalid file path encoding")]
    InvalidPathEncoding,
    #[error("Resource not found")]
    NotFound,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Internal server error")]
    Internal,
    #[error("Invalid path format")]
    InvalidPath,
    #[error("Task execution failed")]
    TaskJoin(#[from] tokio::task::JoinError),
    #[error("Numerical conversion error")]
    TryFromInt(#[from] std::num::TryFromIntError),
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => AppError::NotFound,
            std::io::ErrorKind::PermissionDenied => AppError::PermissionDenied,
            _ => AppError::Internal,
        }
    }
}

impl
    From<(
        std::path::PathBuf,
        (utils::cache::metadata::DirectoryLookupContext, u64),
    )> for AppError
{
    fn from(
        _: (
            std::path::PathBuf,
            (utils::cache::metadata::DirectoryLookupContext, u64),
        ),
    ) -> Self {
        AppError::Internal
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        log_error!("API error: {}", self);
        match self {
            Self::PermissionDenied | Self::PathTraversal => {
                axum::http::StatusCode::FORBIDDEN.into_response()
            }
            Self::InvalidPathEncoding | Self::InvalidPath => {
                axum::http::StatusCode::BAD_REQUEST.into_response()
            }
            Self::NotFound => axum::http::StatusCode::NOT_FOUND.into_response(),
            Self::Internal | Self::TaskJoin(_) | Self::TryFromInt(_) => {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct PathQuery {
    path: String,
}

struct AppState {
    meta_cache: scc::HashCache<
        std::path::PathBuf,
        (
            std::sync::Arc<utils::cache::metadata::DirectoryLookupContext>,
            tokio::time::Instant,
        ),
    >,
    base_path: std::path::PathBuf,
    cache_stats: utils::stats::Cache,
}

const CACHE_TTL_SECONDS: u64 = 30;

fn dedotify_path(path: &str) -> Result<Option<String>, AppError> {
    let mut stack = Vec::new();

    // Split the path into segments based on `/`
    for segment in path.split('/') {
        match segment {
            "" | "." => {
                continue;
            }
            ".." => {
                if stack.pop().is_none() {
                    return Err(AppError::PathTraversal);
                }
            }
            _ => {
                stack.push(segment);
            }
        }
    }

    if stack.is_empty() {
        Ok(None)
    } else {
        Ok(Some(stack.join("/")))
    }
}

fn create_buffer_serialized(metadata: &std::fs::Metadata) -> Result<Vec<u8>, AppError> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(512);

    let created_secs = crate::utils::windows::time::IntoFileTime::into_file_time(
        metadata
            .created()
            .unwrap_or_else(|_| std::time::SystemTime::now()),
    );

    let modified_secs = crate::utils::windows::time::IntoFileTime::into_file_time(
        metadata
            .modified()
            .unwrap_or_else(|_| std::time::SystemTime::now()),
    );

    let accessed_secs = crate::utils::windows::time::IntoFileTime::into_file_time(
        metadata
            .accessed()
            .unwrap_or_else(|_| std::time::SystemTime::now()),
    );

    let entry = crate::generated::blorg_meta_flat::DirectoryEntryMetadata::create(
        &mut builder,
        &crate::generated::blorg_meta_flat::DirectoryEntryMetadataArgs {
            size: metadata.len(),
            created: created_secs,
            modified: modified_secs,
            accessed: accessed_secs,
            directory: metadata.is_dir(),
        },
    );

    // Finish building the buffer
    builder.finish(entry, None);

    // Return the serialized buffer
    Ok(builder.finished_data().to_vec())
}

fn validate_path(
    base_dir: &std::path::Path,
    requested_path: &str,
) -> Result<std::path::PathBuf, AppError> {
    log_debug!(
        "Starting path validation for '{}' in base_dir '{:?}'",
        requested_path,
        base_dir
    );

    let requested = dedotify_path(&requested_path.replace('\\', "/"))?;

    requested.map_or_else(
        || Ok(base_dir.to_owned()),
        |requested| Ok(base_dir.join(requested)),
    )
}

async fn get_dir_entry_info_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<PathQuery>,
) -> Result<Vec<u8>, AppError> {
    log_info!("[FILE INFO] Handling request for: {}", &params.path);

    let canonicalized_path =
        tokio::fs::canonicalize(&validate_path(&data.base_path, &params.path)?).await?;
    log_trace!("Validated canonical path: {:?}", &canonicalized_path);

    if !canonicalized_path.starts_with(&data.base_path) {
        return Err(AppError::PathTraversal);
    }

    let parent_dir = canonicalized_path.parent().ok_or_else(|| {
        log_warn!("Invalid file path structure: {:?}", &canonicalized_path);
        AppError::InvalidPath
    })?;

    log_debug!("Checking cache for parent directory: {:?}", parent_dir);

    if let Some(entry) = data
        .meta_cache
        .read_async(parent_dir, |_, v| v.clone())
        .await
    {
        let (cached_meta, timestamp) = entry;

        let now = tokio::time::Instant::now();

        log_trace!(
            "Cache entry found - Timestamp: {:?}, Current: {:?}, TTL: {}",
            timestamp,
            now,
            CACHE_TTL_SECONDS
        );

        if now - timestamp < tokio::time::Duration::from_secs(CACHE_TTL_SECONDS) {
            data.cache_stats.increment_hits();
            log_debug!("Cache hit for directory: {:?}", parent_dir);

            let file_name = canonicalized_path
                .file_name()
                .ok_or(AppError::InvalidPath)?
                .to_str()
                .ok_or(AppError::InvalidPathEncoding)?;

            return cached_meta
                .get_dir_entry_serialized(
                    file_name,
                    tokio::fs::metadata(&canonicalized_path).await?.is_dir(),
                )
                .ok_or(AppError::Internal);
        }

        log_debug!("Cache entry expired for: {:?}", &parent_dir);
        _ = data
            .meta_cache
            .remove_if_async(&canonicalized_path, |entry| entry.1 == timestamp)
            .await;
    }

    data.cache_stats.increment_misses();

    log_info!("Fetching fresh metadata for: {:?}", &canonicalized_path);
    let meta = tokio::fs::metadata(&canonicalized_path).await?;

    let file_entry = create_buffer_serialized(&meta).map_err(|e| {
        log_error_with_context!(e, "Failed to create directory entry");
        e
    })?;

    Ok(file_entry)
}

async fn create_meta_cache_entry(
    path: std::path::PathBuf,
) -> Result<utils::cache::metadata::DirectoryLookupContext, AppError> {
    log_debug!("Building new cache entry for directory: {:?}", &path);
    tokio::task::spawn_blocking({
        move || -> Result<_, AppError> {
            log_debug!("Scanning directory: {:?}", &path);

            let mut cache_entry = utils::cache::metadata::DirectoryLookupContext::new();
            let dir = std::fs::read_dir(&path).map_err(|e| {
                log_warn_with_context!(e, "Failed to read directory {:?}", &path);
                e
            })?;

            for entry_result in dir {
                match entry_result {
                    Ok(entry) => {
                        log_trace!("Processing entry: {:?}", entry.path());

                        let Ok(name) = entry.file_name().into_string() else {
                            log_debug!("Invalid filename encoding: {:?}", &entry.path());
                            continue;
                        };

                        match entry.metadata() {
                            Ok(metadata) => {
                                if metadata.is_dir() {
                                    cache_entry.add_subdir(&metadata, &name);
                                } else {
                                    cache_entry.add_file(&metadata, &name);
                                }
                            }
                            Err(e) => {
                                log_warn_with_context!(e, "Failed to get metadata for {}", &name);
                            }
                        }
                    }
                    Err(e) => {
                        log_debug_with_context!(e, "Error reading directory entry");
                    }
                }
            }
            log_info!("Directory scan complete - Path: {:?}", &path);

            Ok(cache_entry)
        }
    })
    .await?
}

async fn get_dir_info_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<PathQuery>,
) -> Result<Vec<u8>, AppError> {
    log_info!("[DIR INFO] Handling request for: {}", &params.path);

    let canonicalized_path =
        tokio::fs::canonicalize(&validate_path(&data.base_path, &params.path)?).await?;
    log_trace!("Validated canonical path: {:?}", &canonicalized_path);

    if !canonicalized_path.starts_with(&data.base_path) {
        return Err(AppError::PathTraversal);
    }

    if !tokio::fs::metadata(&canonicalized_path).await?.is_dir() {
        log_debug!("Path is not a directory: {:?}", &canonicalized_path);
        return Err(AppError::NotFound);
    }

    log_debug!("Checking cache for directory: {:?}", &canonicalized_path);
    if let Some(cache_entry) = data
        .meta_cache
        .read_async(&canonicalized_path, |_, v| v.clone())
        .await
    {
        let (cached_dir_meta, timestamp) = cache_entry;

        let now = tokio::time::Instant::now();

        log_trace!(
            "Cache entry found - Timestamp: {:?}, Current: {:?}, TTL: {}",
            timestamp,
            now,
            CACHE_TTL_SECONDS
        );

        if now - timestamp < tokio::time::Duration::from_secs(CACHE_TTL_SECONDS) {
            data.cache_stats.increment_hits();
            log_debug!("Cache hit for directory: {:?}", &canonicalized_path);
            return Ok(cached_dir_meta.get_all_entries_serialized());
        }

        log_debug!("Expired cache entry: {:?}", &canonicalized_path);
        _ = data
            .meta_cache
            .remove_if_async(&canonicalized_path, |entry| entry.1 == timestamp)
            .await;
    }

    data.cache_stats.increment_misses();

    let directory_entry = &create_meta_cache_entry(canonicalized_path.clone()).await?;

    _ = data
        .meta_cache
        .put_async(
            canonicalized_path,
            (
                std::sync::Arc::new(directory_entry.clone()),
                tokio::time::Instant::now(),
            ),
        )
        .await
        .map_err(|e| {
            log_warn_with_context!(e, "Failed to insert entry into cache");
            e
        });

    Ok(directory_entry.get_all_entries_serialized())
}

async fn file_download_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<PathQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    log_info!("[FILE READ] Handling request for: {}", &params.path);

    let canonicalized_path =
        tokio::fs::canonicalize(&validate_path(&data.base_path, &params.path)?).await?;

    log_debug!(
        "Serving file from validated path: {:?}",
        &canonicalized_path
    );

    if !canonicalized_path.starts_with(&data.base_path) {
        return Err(AppError::PathTraversal);
    }

    Ok(tower_http::services::ServeFile::new(&canonicalized_path)
        .try_call(request)
        .await?)
}

async fn find_path_handler(
    axum::extract::State(data): axum::extract::State<std::sync::Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<PathQuery>,
) -> Result<(axum::http::StatusCode, &'static str), AppError> {
    log_info!("[FIND PATH] Handling request for: {}", &params.path);

    let canonicalized_path =
        tokio::fs::canonicalize(&validate_path(&data.base_path, &params.path)?).await?;

    log_debug!(
        "Checking file from validated path: {:?}",
        &canonicalized_path
    );

    if !canonicalized_path.starts_with(&data.base_path) {
        return Err(AppError::PathTraversal);
    }

    match tokio::fs::metadata(canonicalized_path).await?.is_dir() {
        true => Ok((axum::http::StatusCode::FOUND, "1")),
        false => Ok((axum::http::StatusCode::FOUND, "0")),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
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

    let path: std::path::PathBuf = {
        let base_path = std::path::Path::new(&path_argument);

        if !base_path.exists() {
            log_error!("Provided path '{}' does not exist", &path_argument);
            std::process::exit(1);
        }

        if !base_path.is_dir() {
            log_error!("Provided path '{}' is not a directory", &path_argument);
            std::process::exit(1);
        }

        let base_metadata = match std::fs::symlink_metadata(&path_argument) {
            Ok(m) => m,
            Err(e) => {
                log_error_with_context!(e, "Error accessing metadata for '{}'", &path_argument);
                std::process::exit(1);
            }
        };

        if base_metadata.file_type().is_symlink() {
            log_error!("Provided path '{}' is a symlink", &path_argument);
            std::process::exit(1);
        }

        match base_path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                log_error_with_context!(e, "Failed to canonicalize path '{}'", &path_argument);
                std::process::exit(1);
            }
        }
    };

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let state = std::sync::Arc::new(AppState {
        meta_cache: scc::HashCache::with_capacity(1000, 20000),
        base_path: path.clone(),
        cache_stats: utils::stats::Cache::new(),
    });

    #[cfg(feature = "stats")]
    start_cache_statistics_logger(axum::extract::State(state.clone()));

    if let Err(e) = start_fs_watcher(path.clone(), state.clone()) {
        log_error_with_context!(e, "Failed to create file watcher");
        std::process::exit(1);
    }

    let app = axum::Router::new()
        .route(
            "/get_dir_entry_info",
            axum::routing::get(get_dir_entry_info_handler),
        )
        .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
        .route("/get_file", axum::routing::get(file_download_handler))
        .route("/get_file", axum::routing::head(file_download_handler))
        .route("/find_path", axum::routing::get(find_path_handler))
        .route(
            "/healthcheck",
            axum::routing::get(|| async { axum::http::StatusCode::OK }),
        )
        .with_state(state);

    // Start server
    log_info!("Starting server on port {} serving path: {:?}", port, &path);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn start_fs_watcher(
    path: std::path::PathBuf,
    state: std::sync::Arc<AppState>,
) -> Result<(), notify_debouncer_full::notify::Error> {
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
                Ok(events) => {
                    utils::cache::metadata::handle_fs_events(&events, &state.meta_cache).await;
                }
                Err(e) => {
                    log_error_with_context!(e, "watch receive error");
                }
            }
        }
        Ok::<(), notify_debouncer_full::notify::Error>(())
    });

    Ok(())
}

#[cfg(feature = "stats")]
fn start_cache_statistics_logger(state: axum::extract::State<std::sync::Arc<AppState>>) {
    tokio::spawn(async move {
        const STATS_LOG_INTERVAL_SECONDS: u64 = 30;
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(STATS_LOG_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            let (hits, misses) = state.cache_stats.get();
            let total = hits + misses;
            let hit_rate = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            log_info!(
                "Cache Statistics: Hits={}, Misses={}, Hit Rate={:.2}%, Total={}",
                hits,
                misses,
                hit_rate,
                total
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
    use std::path::PathBuf;
    use std::sync::Arc;
    use tower::{Service, util::ServiceExt};

    // Test setup helper
    async fn setup_test_env() -> (PathBuf, Arc<AppState>) {
        let base_dir = tempfile::tempdir().unwrap().into_path();
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

        let state = std::sync::Arc::new(AppState {
            meta_cache: scc::HashCache::with_capacity(1000, 20000),
            base_path: base_dir.clone(),
            cache_stats: utils::stats::Cache::new(),
        });

        if let Err(e) = start_fs_watcher(base_dir.clone(), state.clone()) {
            log_error_with_context!(e, "Failed to create file watcher");
            std::process::exit(1);
        }

        (base_dir, state)
    }

    mod misc {
        use super::*;

        #[tokio::test]
        async fn test_timestamps_consistency() {
            let (_temp_dir, state) = setup_test_env().await;

            // Create a directory with one subdirectory
            let parent_dir = _temp_dir.join("timestamp_test");
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
            let fb_file: DirectoryEntryMetadata =
                flatbuffers::root::<DirectoryEntryMetadata>(&bytes).unwrap();

            assert!(!fb_file.directory());
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
            let file_names = fb_dir.files().unwrap().name().unwrap();
            let file_index = file_names
                .iter()
                .position(|n| n == "test_file.txt")
                .unwrap();

            // Verify file timestamps from directory listing
            assert_eq!(
                fb_dir.files().unwrap().created().unwrap().get(file_index),
                file_created_expected
            );
            assert_eq!(
                fb_dir.files().unwrap().modified().unwrap().get(file_index),
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

            let dir_names = fb_dir.directories().unwrap().name().unwrap();
            let dir_index = dir_names.iter().position(|n| n == "subdirectory").unwrap();

            assert_eq!(
                fb_dir
                    .directories()
                    .unwrap()
                    .created()
                    .unwrap()
                    .get(dir_index),
                subdir_created_expected
            );
            assert_eq!(
                fb_dir
                    .directories()
                    .unwrap()
                    .modified()
                    .unwrap()
                    .get(dir_index),
                subdir_modified_expected
            );
        }

        #[tokio::test]
        async fn test_concurrent_cache_access() {
            // needs some code
            let (_temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let mut results = vec![];

            for _ in 0..100000 {
                let req = Request::builder()
                    .uri("/get_dir_info?path=test_dir")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap();
                results.push(app.call(req).await.unwrap().status());
            }

            for result in results {
                assert_eq!(result, http::StatusCode::OK);
            }

            // Ensure cache stats reflect the concurrent hits/misses appropriately
            #[cfg(feature = "stats")]
            assert_eq!(state.cache_stats.get().0, 99999); // 1 miss + 99999 hits
        }
    }

    mod dir_entry_info {
        use super::*;

        #[tokio::test]
        async fn test_valid_file_info() {
            let (_temp_dir, state) = setup_test_env().await;

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
            let (_temp_dir, state) = setup_test_env().await;

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
            let (temp_dir, state) = setup_test_env().await;
            let mut path = temp_dir.clone();
            for depth in 0..10 {
                path = path.join(format!("level_{}", depth));
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
        async fn test_file_and_data_changes() {
            let (temp_dir, state) = setup_test_env().await;
            let file_path = temp_dir.join("modifiable.txt");
            File::create(&file_path).unwrap().write_all(b"v1").unwrap();

            // obtain file metadata like creation time
            let metadata = fs::metadata(&file_path).unwrap();

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
                .uri("/get_dir_entry_info?path=modifiable.txt")
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
            assert!(!fb_data.directory());

            // Modify the file
            File::create(&file_path)
                .unwrap()
                .write_all(b"updated")
                .unwrap();

            // Fast-forward time beyond TTL
            if let Some(mut foo) = state.meta_cache.get_async(&temp_dir).await {
                let bar = foo.get_mut();
                bar.1 -= tokio::time::Duration::from_secs(CACHE_TTL_SECONDS); // Set timestamp to simulate expiration
            }

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

            assert_eq!(fb_data.size(), 7);
            assert_eq!(fb_data.created(), created_secs);
        }

        #[tokio::test]
        async fn test_folder_and_data_changes() {
            let (temp_dir, state) = setup_test_env().await;
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
            let (_temp_dir, state) = setup_test_env().await;

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

            let directory_count = fb_data.directory_count();
            let file_count = fb_data.file_count();

            assert_eq!(
                fb_data.directories().unwrap().name().unwrap().len() as u64,
                directory_count
            );

            assert_eq!(
                fb_data.files().unwrap().name().unwrap().len() as u64,
                file_count
            );

            assert_eq!(
                fb_data.files().unwrap().name().unwrap().get(0),
                "file_in_dir.txt"
            );
        }

        #[tokio::test]
        async fn test_special_char_filenames() {
            let (temp_dir, state) = setup_test_env().await;
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
            let entries = fb_data.files().unwrap().name().unwrap();

            for name in file_names {
                assert!(entries.iter().any(|e| e == name));
            }
        }

        #[tokio::test]
        async fn test_directory_with_mixed_contents() {
            let (_temp_dir, state) = setup_test_env().await;

            // Create directory with multiple subdirectories and files
            let mixed_dir = _temp_dir.join("mixed_dir");
            fs::create_dir(&mixed_dir).unwrap();

            // Create subdirectories
            for i in 1..=3 {
                fs::create_dir(mixed_dir.join(format!("subdir_{}", i))).unwrap();
            }

            // Create files
            for i in 1..=5 {
                File::create(mixed_dir.join(format!("file_{}.txt", i)))
                    .unwrap()
                    .write_all(format!("content {}", i).as_bytes())
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
            assert_eq!(fb_data.directory_count(), 3);
            assert_eq!(fb_data.file_count(), 5);

            // Verify all directory info arrays have the same length
            let dir_names = fb_data.directories().unwrap().name().unwrap();
            assert_eq!(dir_names.len(), 3);
            assert_eq!(fb_data.directories().unwrap().size().unwrap().len(), 3);
            assert_eq!(fb_data.directories().unwrap().created().unwrap().len(), 3);
            assert_eq!(fb_data.directories().unwrap().modified().unwrap().len(), 3);
            assert_eq!(fb_data.directories().unwrap().accessed().unwrap().len(), 3);

            // Verify all file info arrays have the same length
            let file_names = fb_data.files().unwrap().name().unwrap();
            assert_eq!(file_names.len(), 5);
            assert_eq!(fb_data.files().unwrap().size().unwrap().len(), 5);
            assert_eq!(fb_data.files().unwrap().created().unwrap().len(), 5);
            assert_eq!(fb_data.files().unwrap().modified().unwrap().len(), 5);
            assert_eq!(fb_data.files().unwrap().accessed().unwrap().len(), 5);

            // Verify directory names are present
            let dir_names_set: std::collections::HashSet<&str> = dir_names.iter().collect();
            assert!(dir_names_set.contains("subdir_1"));
            assert!(dir_names_set.contains("subdir_2"));
            assert!(dir_names_set.contains("subdir_3"));

            // Verify file names are present
            let file_names_set: std::collections::HashSet<&str> = file_names.iter().collect();
            assert!(file_names_set.contains("file_1.txt"));
            assert!(file_names_set.contains("file_2.txt"));
            assert!(file_names_set.contains("file_3.txt"));
            assert!(file_names_set.contains("file_4.txt"));
            assert!(file_names_set.contains("file_5.txt"));
        }

        #[tokio::test]
        async fn test_directory_metadata_fields() {
            let (_temp_dir, state) = setup_test_env().await;

            // Create nested directory structure with specific timestamps if possible
            let nested_dir = _temp_dir.join("nested_test_dir");
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
            assert_eq!(fb_data.directory_count(), 1);
            assert_eq!(fb_data.file_count(), 0);

            // Verify directory name
            assert_eq!(
                fb_data.directories().unwrap().name().unwrap().get(0),
                "sub_directory"
            );

            // Check that metadata arrays all have the same length
            assert_eq!(fb_data.directories().unwrap().name().unwrap().len(), 1);
            assert_eq!(fb_data.directories().unwrap().size().unwrap().len(), 1);
            assert_eq!(fb_data.directories().unwrap().created().unwrap().len(), 1);
            assert_eq!(fb_data.directories().unwrap().modified().unwrap().len(), 1);
            assert_eq!(fb_data.directories().unwrap().accessed().unwrap().len(), 1);

            // Check that times are in the expected range (non-zero and recent)
            let created = fb_data.directories().unwrap().created().unwrap().get(0);
            let modified = fb_data.directories().unwrap().modified().unwrap().get(0);
            let accessed = fb_data.directories().unwrap().accessed().unwrap().get(0);

            assert!(created > 0);
            assert!(modified > 0);
            assert!(accessed > 0);
        }
    }

    mod find_path_handler {
        use super::*;

        #[tokio::test]
        async fn test_find_path_existing() {
            let (_temp_dir, state) = setup_test_env().await;

            let app = Router::new()
                .route("/find_path", axum::routing::get(find_path_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/find_path?path=test_file.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::FOUND);
        }

        #[tokio::test]
        async fn test_find_path_filetype_validation() {
            let (_temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/find_path", axum::routing::get(find_path_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/find_path?path=test_file.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app.call(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::FOUND);
            assert_eq!(resp.collect().await.unwrap().to_bytes()[0], b'0');

            let req = Request::builder()
                .uri("/find_path?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.call(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::FOUND);
            assert_eq!(resp.collect().await.unwrap().to_bytes()[0], b'1');
        }

        #[tokio::test]
        async fn test_find_path_nonexistent() {
            let (_temp_dir, state) = setup_test_env().await;

            let app = Router::new()
                .route("/find_path", axum::routing::get(find_path_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/find_path?path=nonexistent.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_find_path_path_traversal() {
            let (_temp_dir, state) = setup_test_env().await;

            let app = Router::new()
                .route("/find_path", axum::routing::get(find_path_handler))
                .with_state(state);

            let req = Request::builder()
                .uri("/find_path?path=../passwd.txt")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }
    }

    mod file_download {
        use super::*;

        #[tokio::test]
        async fn test_file_download() {
            let (_temp_dir, state) = setup_test_env().await;

            let app = Router::new()
                .route("/get_file", axum::routing::get(file_download_handler))
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
            let (_temp_dir, state) = setup_test_env().await;

            let app = Router::new()
                .route("/get_file", axum::routing::get(file_download_handler))
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
            let (_temp_dir, state) = setup_test_env().await;

            let app = Router::new()
                .route("/get_file", axum::routing::head(file_download_handler))
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

        #[cfg(feature = "stats")]
        #[tokio::test]
        async fn test_cache_behavior() {
            let (_temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            // First request (cache miss)
            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();
            assert_eq!(state.cache_stats.get().0, 0);
            assert_eq!(state.cache_stats.get().1, 1);

            // Second request (cache hit)
            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();
            assert_eq!(state.cache_stats.get().0, 1);
            assert_eq!(state.cache_stats.get().1, 1);
        }

        #[cfg(feature = "stats")]
        #[tokio::test]
        async fn test_cache_expiration() {
            let (_temp_dir, state) = setup_test_env().await;

            // Manually insert an expired cache entry
            let path = state.base_path.join("test_dir");

            state
                .meta_cache
                .put_async(
                    path.clone(),
                    (
                        std::sync::Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                        tokio::time::Instant::now()
                            - tokio::time::Duration::from_secs(CACHE_TTL_SECONDS),
                    ),
                )
                .await
                .unwrap();

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
            // Verify cache was updated
            assert_eq!(state.cache_stats.get().1, 1); // Should count as miss
        }

        #[tokio::test]
        async fn test_cache_invalidation_after_modification() {
            let (temp_dir, state) = setup_test_env().await;
            let file_path = temp_dir.join("modifiable.txt");
            File::create(&file_path).unwrap().write_all(b"v1").unwrap();

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

            assert_eq!(fb_data.size(), 2);

            // Fast-forward time beyond TTL
            if let Some(mut foo) = state.meta_cache.get_async(&temp_dir).await {
                let bar = foo.get_mut();
                bar.1 -= tokio::time::Duration::from_secs(CACHE_TTL_SECONDS); // Set timestamp to simulate expiration
            }

            // Modify the file
            File::create(&file_path)
                .unwrap()
                .write_all(b"updated")
                .unwrap();

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

            assert_eq!(fb_data.size(), 7);
        }
    }
    mod security {
        use super::*;

        #[tokio::test]
        async fn test_path_traversal_protection_posix() {
            let (_temp_dir, state) = setup_test_env().await;

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
            let (_temp_dir, state) = setup_test_env().await;

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

        #[tokio::test]
        #[cfg(unix)]
        async fn test_permission_denied() {
            let (temp_dir, state) = setup_test_env().await;
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
            let (temp_dir, state) = setup_test_env().await;

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
                .route("/get_file", axum::routing::get(file_download_handler))
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

    mod file_events {
        use super::*;

        #[tokio::test]
        async fn test_handle_fs_events_create_file() {
            // Setup test cache
            let (temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let req = Request::builder()
                .uri("/get_dir_info?path=.")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir/nested_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            // invalidate by creating test_dir/nested_test_dir/file_in_nested_test_dir2.txt
            File::create_new(
                temp_dir.join("test_dir/nested_test_dir/file_in_nested_test_dir2.txt"),
            )
            .unwrap();

            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

            // Verify cache state
            assert!(
                !state
                    .meta_cache
                    .contains_async(&temp_dir.join("test_dir/nested_test_dir"))
                    .await,
                "parent path should be removed from cache"
            );
            assert!(
                state
                    .meta_cache
                    .contains_async(&temp_dir.join("test_dir"))
                    .await,
                "grandparent should remain in cache"
            );
        }

        #[tokio::test]
        async fn test_handle_fs_events_rename_directory() {
            // Setup test cache
            let (temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let req = Request::builder()
                .uri("/get_dir_info?path=.")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir/nested_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            // invalidate by renaming test_dir
            fs::rename(temp_dir.join("test_dir"), temp_dir.join("test_dir_renamed")).unwrap();

            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

            // Verify cache state
            assert!(
                !state
                    .meta_cache
                    .contains_async(&temp_dir.join("test_dir"))
                    .await,
                "path should be removed from cache"
            );
            assert!(
                !state.meta_cache.contains_async(&temp_dir).await,
                "parent path should be removed from cache"
            );
            assert!(
                !state
                    .meta_cache
                    .contains_async(&temp_dir.join("test_dir/nested_test_dir"))
                    .await,
                "child path should be removed in cache"
            );
        }

        #[tokio::test]
        async fn test_handle_fs_events_rename_file() {
            // Setup test cache
            let (temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let req = Request::builder()
                .uri("/get_dir_info?path=.")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir/nested_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            // invalidate by renaming test_dir
            fs::rename(
                temp_dir.join("test_dir/file_in_dir.txt"),
                temp_dir.join("test_dir/file_in_dir_renamed.txt"),
            )
            .unwrap();

            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

            // Verify cache state
            assert!(
                !state
                    .meta_cache
                    .contains_async(&temp_dir.join("test_dir"))
                    .await,
                "parent path should be removed from cache"
            );

            assert!(
                state.meta_cache.contains_async(&temp_dir).await,
                "grandparent path should remain in cache"
            );
        }

        #[tokio::test]
        async fn test_handle_fs_events_remove_file() {
            // Setup test cache
            let (temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let req = Request::builder()
                .uri("/get_dir_info?path=.")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir/nested_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=other_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            // invalidate by deleting ./test_dir/file_in_dir.txt
            fs::remove_file(temp_dir.join("test_dir/file_in_dir.txt")).unwrap();

            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

            // Verify cache state
            assert!(
                !state
                    .meta_cache
                    .contains_async(&temp_dir.join("test_dir"))
                    .await,
                "parent path should be removed from cache"
            );
            assert!(
                state.meta_cache.contains_async(&temp_dir).await,
                "grandparent should remain in cache"
            );
            assert!(
                state
                    .meta_cache
                    .contains_async(&temp_dir.join("other_test_dir"))
                    .await,
                "parent's siblings should remain in cache"
            );
        }

        #[tokio::test]
        async fn test_handle_fs_events_remove_directory() {
            // Setup test cache
            let (temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let req = Request::builder()
                .uri("/get_dir_info?path=.")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir/nested_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            // invalidate by deleting ./test_dir

            fs::remove_dir_all(temp_dir.join("test_dir")).unwrap();

            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

            assert!(
                state.meta_cache.is_empty(),
                "Cache should be cleared but isnt. Contains {} entries",
                state.meta_cache.len()
            );
        }

        #[tokio::test]
        async fn test_handle_fs_events_remove_directory_after_fresh_entry_insertion() {
            // Setup test cache
            let (temp_dir, state) = setup_test_env().await;

            let mut app = Router::new()
                .route("/get_dir_info", axum::routing::get(get_dir_info_handler))
                .with_state(state.clone());

            let req = Request::builder()
                .uri("/get_dir_info?path=.")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            let req = Request::builder()
                .uri("/get_dir_info?path=test_dir/nested_test_dir")
                .method("GET")
                .body(Body::empty())
                .unwrap();

            _ = app.call(req).await.unwrap();

            {
                let mut base_entry = state.meta_cache.get(&temp_dir).unwrap();
                let (_, timestamp) = base_entry.get_mut();
                *timestamp += std::time::Duration::from_secs(CACHE_TTL_SECONDS);
            }
            {
                let mut affected_entry = state.meta_cache.get(&temp_dir.join("test_dir")).unwrap();
                let (_, timestamp) = affected_entry.get_mut();
                *timestamp += std::time::Duration::from_secs(CACHE_TTL_SECONDS);
            }
            {
                let mut child_entry = state
                    .meta_cache
                    .get(&temp_dir.join("test_dir/nested_test_dir"))
                    .unwrap();
                let (_, timestamp) = child_entry.get_mut();
                *timestamp += std::time::Duration::from_secs(CACHE_TTL_SECONDS);
            }
            // invalidate by deleting ./test_dir

            fs::remove_dir_all(temp_dir.join("test_dir")).unwrap();

            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

            assert!(
                !state.meta_cache.is_empty(),
                "Cache should not be cleared but is. Contains no entries"
            );
        }
    }
}
