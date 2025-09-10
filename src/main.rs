#![deny(clippy::all, clippy::pedantic)]

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
mod utils;

// TODO:
// File serving caching/chunking

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Path traversal attempt detected")]
    PathTraversal,
    #[error("Resource not found")]
    NotFound,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Internal server error")]
    Internal,
    #[error("Invalid path format")]
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
    directory_cache: moka::future::Cache<
        std::path::PathBuf,
        std::sync::Arc<utils::cache::metadata::DirectoryLookupContext>,
    >,
    file_cache: moka::future::Cache<std::path::PathBuf, utils::cache::metadata::EntryType>,
    base_path: std::path::PathBuf,
    cache_stats: utils::stats::Cache,
}

const CACHE_TTL_SECONDS: u64 = 5 * 60; // 5 MIN
const CACHE_TTI_SECONDS: u64 = 60; // 1 MIN

fn dedotify_path(path: &str) -> Result<Option<String>, AppError> {
    let mut stack = Vec::new();

    // Split the path into segments based on `/`
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
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

fn create_buffer_serialized(metadata: &std::fs::Metadata) -> Vec<u8> {
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
    builder.finished_data().to_vec()
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

    if let Some(entry) = data.file_cache.get(&canonicalized_path).await {
        data.cache_stats.increment_hits();
        log_debug!("Cache hit for directory entry: {:?}", &canonicalized_path);
        return Ok(entry.get_dir_entry_serialized());
    }

    data.cache_stats.increment_misses();

    log_info!("Fetching fresh metadata for: {:?}", &canonicalized_path);
    let meta = tokio::fs::metadata(&canonicalized_path).await?;

    if meta.is_dir() {
        data.file_cache
            .insert(
                canonicalized_path,
                utils::cache::metadata::EntryType::Directory(
                    utils::cache::metadata::DirectoryEntry::new(&meta),
                ),
            )
            .await;
    } else {
        data.file_cache
            .insert(
                canonicalized_path,
                utils::cache::metadata::EntryType::File(utils::cache::metadata::FileEntry::new(
                    &meta,
                )),
            )
            .await;
    }

    Ok(create_buffer_serialized(&meta))
}

async fn create_directory_listing_cache_entry(
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

            let entries: Vec<(std::fs::Metadata, String, bool)> = dir
                .filter_map(|entry_result| match entry_result {
                    Ok(entry) => {
                        log_trace!("Processing entry: {:?}", entry.path());

                        let Ok(name) = entry.file_name().into_string() else {
                            log_debug!("Invalid filename encoding: {:?}", &entry.path());
                            return None;
                        };

                        match entry.metadata() {
                            Ok(metadata) => {
                                let is_directory = metadata.is_dir();
                                Some((metadata, name, is_directory))
                            }
                            Err(e) => {
                                log_warn_with_context!(e, "Failed to get metadata for {}", &name);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        log_debug_with_context!(e, "Error reading directory entry");
                        None
                    }
                })
                .collect();

            // Batch add all entries at once
            cache_entry.add_entries_batch(entries);

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
    if let Some(cached_directory_entry) = data.directory_cache.get(&canonicalized_path).await {
        data.cache_stats.increment_hits();
        log_debug!("Cache hit for directory: {:?}", &canonicalized_path);
        return Ok(cached_directory_entry.get_all_entries_serialized());
    }

    data.cache_stats.increment_misses();

    let directory_entry = &create_directory_listing_cache_entry(canonicalized_path.clone()).await?;

    data.directory_cache
        .insert(
            canonicalized_path,
            std::sync::Arc::new(directory_entry.clone()),
        )
        .await;

    Ok(directory_entry.get_all_entries_serialized())
}

async fn get_file_handler(
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
        directory_cache: moka::future::Cache::builder()
            .max_capacity(5000)
            .time_to_live(std::time::Duration::from_secs(CACHE_TTL_SECONDS))
            .time_to_idle(std::time::Duration::from_secs(CACHE_TTI_SECONDS))
            .build(),
        file_cache: moka::future::Cache::builder()
            .max_capacity(5000)
            .time_to_live(std::time::Duration::from_secs(CACHE_TTL_SECONDS))
            .time_to_idle(std::time::Duration::from_secs(CACHE_TTI_SECONDS))
            .build(),
        base_path: path.clone(),
        cache_stats: utils::stats::Cache::new(),
    });

    #[cfg(feature = "stats")]
    start_cache_statistics_logger(axum::extract::State(state.clone()));

    start_fs_watcher(path.clone(), state.clone());

    let app = axum::Router::new()
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
        .with_state(state);

    // Start server
    log_info!("Starting server on port {} serving path: {:?}", port, &path);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn start_fs_watcher(path: std::path::PathBuf, state: std::sync::Arc<AppState>) {
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
                    utils::cache::metadata::handle_fs_events(
                        &events,
                        &state.directory_cache,
                        &state.file_cache,
                    )
                    .await;
                }
                Err(e) => {
                    log_error_with_context!(e, "watch receive error");
                }
            }
        }
        Ok::<(), notify_debouncer_full::notify::Error>(())
    });
}

#[cfg(feature = "stats")]
fn start_cache_statistics_logger(state: axum::extract::State<std::sync::Arc<AppState>>) {
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

        let directory_cache = moka::future::Cache::builder()
            .max_capacity(1000)
            .time_to_live(std::time::Duration::from_secs(2))
            .time_to_idle(std::time::Duration::from_secs(1))
            .build();

        let file_cache = moka::future::Cache::builder()
            .max_capacity(1000)
            .time_to_live(std::time::Duration::from_secs(2))
            .time_to_idle(std::time::Duration::from_secs(1))
            .build();

        std::sync::Arc::new(AppState {
            directory_cache,
            file_cache,
            base_path: base_dir.to_path_buf(),
            cache_stats: utils::stats::Cache::new(),
        })
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

            let directory_cache = moka::future::Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(ttl_secs))
                .time_to_idle(Duration::from_secs(idle_secs))
                .build();

            let file_cache = moka::future::Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(ttl_secs))
                .time_to_idle(Duration::from_secs(idle_secs))
                .build();

            Arc::new(AppState {
                directory_cache,
                file_cache,
                base_path: base_dir.to_path_buf(),
                cache_stats: utils::stats::Cache::new(),
            })
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

        #[tokio::test]
        async fn test_cache_ttl_expiration() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env_with_cache_config(temp.path(), 1, 1);

            let path = state.base_path.join("test_dir");
            state
                .directory_cache
                .insert(
                    path.clone(),
                    Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                )
                .await;

            // Should exist initially
            assert!(state.directory_cache.get(&path).await.is_some());

            // Sleep beyond TTL
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // Should now be expired
            assert!(state.directory_cache.get(&path).await.is_none());
        }

        #[tokio::test]
        async fn test_cache_idle_expiration() {
            let temp = tempfile::tempdir().unwrap();
            let state = setup_test_env_with_cache_config(temp.path(), 10, 1);

            let path = state.base_path.join("idle_dir");
            state
                .directory_cache
                .insert(
                    path.clone(),
                    Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                )
                .await;

            // Access the cache to reset idle timer
            assert!(state.directory_cache.get(&path).await.is_some());

            // Sleep just below idle threshold
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            assert!(state.directory_cache.get(&path).await.is_some());

            // Sleep beyond idle threshold
            tokio::time::sleep(std::time::Duration::from_millis(1700)).await;
            assert!(state.directory_cache.get(&path).await.is_none());
        }

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

            let path = temp_dir.join("test_dir");

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
            assert!(state.directory_cache.get(&path).await.is_some());

            // Manually invalidate
            state.directory_cache.invalidate(&path).await;

            // Verify entry is gone
            assert!(state.directory_cache.get(&path).await.is_none());
        }

        #[tokio::test]
        async fn test_cache_invalidation_after_file_modification() {
            // Pause Tokio time for deterministic testing
            tokio::time::pause();

            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env_with_cache_config(temp_dir, 30, 15);

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
            let original_size = fb_data.size();
            assert_eq!(original_size, 2);

            // Verify file is cached
            assert!(state.file_cache.get(&file_path).await.is_some());

            // Modify the file
            File::create(&file_path)
                .unwrap()
                .write_all(b"updated content")
                .unwrap();

            // Advance time slightly to simulate filesystem noticing the change
            tokio::time::advance(Duration::from_millis(10)).await;

            // Invalidate cache to simulate file watcher behavior
            state.file_cache.invalidate(&file_path).await;

            // Verify cache entry is gone
            assert!(state.file_cache.get(&file_path).await.is_none());

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

    mod file_watcher {
        use std::thread::sleep;

        use crate::utils::cache::metadata::FileEntry;

        use super::*;
        #[tokio::test]
        async fn test_file_creation_invalidates_parent_cache() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);
            let test_file_path = temp_dir.join("new_file.txt");

            // 1. Prime the directory cache by inserting a dummy value.
            state
                .directory_cache
                .insert(
                    temp_dir.to_path_buf(),
                    Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                )
                .await;
            assert!(
                state.directory_cache.get(temp_dir).await.is_some(),
                "Cache should be primed"
            );

            // 2. Create a new file, which should trigger the watcher.
            fs::write(&test_file_path, "Hello").expect("Failed to create test file");

            // 3. Wait for the debouncer and event handler to run.
            sleep(std::time::Duration::from_secs(3));

            // 4. Assert that the cache for the parent directory has been invalidated.
            assert!(
                state.directory_cache.get(temp_dir).await.is_none(),
                "Parent directory cache should be invalidated after file creation"
            );
        }

        #[tokio::test]
        async fn test_file_modification_invalidates_caches() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);
            let test_file_path = temp_dir.join("test_file.txt");

            // 1. Create the initial file.
            fs::write(&test_file_path, "Initial content").unwrap();
            // Wait for creation event to settle
            sleep(std::time::Duration::from_secs(3));

            // 2. Prime the caches for the file and its parent directory.
            state
                .directory_cache
                .insert(
                    temp_dir.to_path_buf(),
                    Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                )
                .await;
            state
                .file_cache
                .insert(
                    test_file_path.clone(),
                    utils::cache::metadata::EntryType::File(FileEntry::new(
                        &tokio::fs::metadata(&test_file_path).await.unwrap(),
                    )),
                )
                .await;
            assert!(
                state.directory_cache.get(temp_dir).await.is_some(),
                "Parent cache should be primed"
            );
            assert!(
                state.file_cache.get(&test_file_path).await.is_some(),
                "File cache should be primed"
            );

            // 3. Modify the file.
            fs::write(&test_file_path, "Modified content").unwrap();

            // 4. Wait for the event to be processed.
            sleep(std::time::Duration::from_secs(3));

            // 5. Assert that both caches have been invalidated.
            assert!(
                state.file_cache.get(&test_file_path).await.is_none(),
                "File cache should be invalidated after modification"
            );
            assert!(
                state.directory_cache.get(temp_dir).await.is_none(),
                "Parent directory cache should also be invalidated after modification"
            );
        }

        #[tokio::test]
        async fn test_file_deletion_invalidates_caches() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);
            let test_file_path = temp_dir.join("file_to_delete.txt");

            // 1. Create a file and wait for the event to clear.
            fs::write(&test_file_path, "content").unwrap();
            sleep(std::time::Duration::from_secs(3));

            // 2. Prime the caches.
            state
                .directory_cache
                .insert(
                    temp_dir.to_path_buf(),
                    Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                )
                .await;
            state
                .file_cache
                .insert(
                    test_file_path.clone(),
                    utils::cache::metadata::EntryType::File(FileEntry::new(
                        &tokio::fs::metadata(&test_file_path).await.unwrap(),
                    )),
                )
                .await;
            assert!(
                state.directory_cache.get(temp_dir).await.is_some(),
                "Parent cache should be primed before deletion"
            );
            assert!(
                state.file_cache.get(&test_file_path).await.is_some(),
                "File cache should be primed before deletion"
            );

            // 3. Delete the file.
            fs::remove_file(&test_file_path).unwrap();

            // 4. Wait for the event to be processed.
            sleep(std::time::Duration::from_secs(3));

            // 5. Assert that both caches have been invalidated.
            assert!(
                state.file_cache.get(&test_file_path).await.is_none(),
                "File cache should be invalidated after deletion"
            );
            assert!(
                state.directory_cache.get(temp_dir).await.is_none(),
                "Parent directory cache should be invalidated after deletion"
            );
        }

        #[tokio::test]
        async fn test_directory_creation_and_deletion_invalidates_parent_cache() {
            let temp = tempfile::tempdir().unwrap();
            let temp_dir = temp.path();
            let state = setup_test_env(temp_dir);
            let sub_dir_path = temp_dir.join("subdir");

            // --- Test Directory Creation ---

            // 1. Prime the parent directory cache.
            state
                .directory_cache
                .insert(
                    temp_dir.to_path_buf(),
                    Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                )
                .await;
            assert!(
                state.directory_cache.get(temp_dir).await.is_some(),
                "Parent cache should be primed for creation test"
            );

            // 2. Create a new subdirectory.
            fs::create_dir(&sub_dir_path).unwrap();

            // 3. Wait for the watcher.
            sleep(std::time::Duration::from_secs(3));

            // 4. Assert parent cache is invalidated.
            assert!(
                state.directory_cache.get(temp_dir).await.is_none(),
                "Parent directory cache should be invalidated after sub-directory creation"
            );

            // --- Test Directory Deletion ---

            // 1. Prime the parent cache again.
            state
                .directory_cache
                .insert(
                    temp_dir.to_path_buf(),
                    Arc::new(utils::cache::metadata::DirectoryLookupContext::new()),
                )
                .await;
            assert!(
                state.directory_cache.get(temp_dir).await.is_some(),
                "Parent cache should be re-primed for deletion test"
            );

            // 2. Delete the subdirectory.
            fs::remove_dir(&sub_dir_path).unwrap();

            // 3. Wait for the watcher.
            sleep(std::time::Duration::from_secs(3));

            // 4. Assert parent cache is invalidated again.
            assert!(
                state.directory_cache.get(temp_dir).await.is_none(),
                "Parent directory cache should be invalidated after sub-directory deletion"
            );
        }
    }
}
