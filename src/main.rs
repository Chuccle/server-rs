#![deny(clippy::all)]

mod generated {
    #![allow(clippy::all, unused_imports, dead_code)]
    include!(concat!(
        env!("OUT_DIR"),
        "/metadata_flatbuffer_generated.rs"
    ));
}
mod utils;

// TODO:
// We need to use inotify for cache invalidation, we can then remove timestamp coupled to each entry
// We need to investigate compression on /get_dir_info and /get_file_info
#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Path traversal attempt detected")]
    PathTraversal,
    #[error("Invalid file path encoding")]
    InvalidPathEncoding,
    #[error("Resource not found")]
    NotFound,
    #[error("Internal server error")]
    Internal(#[from] std::io::Error),
    #[error("Invalid path format")]
    InvalidPath,
    #[error("System time error")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("Task execution failed")]
    TaskJoin(#[from] tokio::task::JoinError),
    #[error("Numerical conversion error")]
    TryFromIntError(#[from] std::num::TryFromIntError),
}

impl actix_web::ResponseError for AppError {
    fn error_response(&self) -> actix_web::HttpResponse {
        log_error!("API error: {}", self);
        match self {
            Self::PathTraversal => actix_web::HttpResponse::Forbidden().body(self.to_string()),
            Self::InvalidPathEncoding | Self::InvalidPath => {
                actix_web::HttpResponse::BadRequest().body(self.to_string())
            }
            Self::NotFound => actix_web::HttpResponse::NotFound().body(self.to_string()),
            Self::Internal(_)
            | Self::SystemTime(_)
            | Self::TaskJoin(_)
            | Self::TryFromIntError(_) => {
                actix_web::HttpResponse::InternalServerError().body("Internal server error")
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct FileQuery {
    file_path: String,
}

#[derive(serde::Deserialize)]
struct DirQuery {
    directory: String,
}

#[derive(serde::Deserialize)]
struct FileRequest {
    file_path: String,
}

struct AppState {
    meta_cache:
        scc::HashCache<std::path::PathBuf, (utils::cache::metadata::DirectoryLookupContext, u64)>,
    base_path: std::path::PathBuf,
    cache_stats: utils::stats::Cache,
}

const CACHE_TTL_SECONDS: u64 = 300;

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

fn create_buffer_serialized(metadata: &std::fs::Metadata, name: &str) -> Result<Vec<u8>, AppError> {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(512);

    let name_fb = builder.create_string(name);

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
            name: Some(name_fb),
            size: metadata.len(),
            created: created_secs,
            modified: modified_secs,
            accessed: accessed_secs,
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

async fn get_file_info_handler(
    data: actix_web::web::Data<AppState>,
    params: actix_web::web::Query<FileQuery>,
) -> Result<actix_web::HttpResponse, AppError> {
    log_info!("[FILE INFO] Handling request for: {}", &params.file_path);

    let normalized_requested = validate_path(&data.base_path, &params.file_path)?;
    log_trace!("Validated canonical path: {:?}", &normalized_requested);

    if !normalized_requested.is_file() {
        log_debug!("Path is not a file: {:?}", &normalized_requested);
        return Err(AppError::NotFound);
    }

    let parent_dir = normalized_requested.parent().ok_or_else(|| {
        log_warn!("Invalid file path structure: {:?}", &normalized_requested);
        AppError::InvalidPath
    })?;

    log_debug!("Checking cache for parent directory: {:?}", parent_dir);
    let cache_result = data.meta_cache.get_async(parent_dir).await;

    if let Some(entry) = &cache_result {
        let (cached_meta, timestamp) = entry.get();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        log_trace!(
            "Cache entry found - Timestamp: {}, Current: {}, TTL: {}",
            timestamp,
            now,
            CACHE_TTL_SECONDS
        );

        if now - timestamp < CACHE_TTL_SECONDS {
            data.cache_stats.increment_hits();
            log_debug!("Cache hit for directory: {:?}", parent_dir);

            let file_name = normalized_requested
                .file_name()
                .ok_or(AppError::InvalidPath)?
                .to_str()
                .ok_or(AppError::InvalidPathEncoding)?;

            log_trace!("Looking for file in cache: {}", file_name);

            if let Some(dir_ent) = cached_meta.get_file_serialized(file_name) {
                log_debug!("File found in cache: {}", file_name);
                return Ok(actix_web::HttpResponse::Ok().body(actix_web::web::Bytes::from(dir_ent)));
            }
        } else {
            log_debug!("Cache entry expired for: {:?}", parent_dir);
            data.cache_stats.increment_misses();
        }
    } else {
        log_debug!("Cache miss for directory: {:?}", parent_dir);
        data.cache_stats.increment_misses();
    }

    log_info!("Fetching fresh metadata for: {:?}", &normalized_requested);
    let meta = tokio::fs::symlink_metadata(&normalized_requested)
        .await
        .map_err(|e| {
            log_warn!(
                "Metadata fetch failed for {:?}: {}",
                &normalized_requested,
                e
            );
            AppError::Internal(e)
        })?;

    let file_name = normalized_requested
        .file_name()
        .ok_or(AppError::InvalidPath)?
        .to_str()
        .ok_or(AppError::InvalidPathEncoding)?;

    let file_entry = create_buffer_serialized(&meta, file_name).map_err(|e| {
        log_error_with_context!(e, "Failed to create directory entry for {}", file_name);
        AppError::Internal(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to create directory entry",
        ))
    })?;

    Ok(actix_web::HttpResponse::Ok().body(actix_web::web::Bytes::from(file_entry)))
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
                AppError::Internal(e)
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
    .await
    .map_err(|e| {
        log_error!("Directory processing task failed: {}", e);
        AppError::TaskJoin(e)
    })?
}

async fn get_dir_info_handler(
    data: actix_web::web::Data<AppState>,
    params: actix_web::web::Query<DirQuery>,
) -> Result<actix_web::HttpResponse, AppError> {
    log_info!("[DIR INFO] Handling request for: {}", &params.directory);

    let normalized_requested = validate_path(&data.base_path, &params.directory)?;
    log_trace!("Validated canonical path: {:?}", &normalized_requested);

    if !normalized_requested.is_dir() {
        log_debug!("Path is not a directory: {:?}", &normalized_requested);
        return Err(AppError::NotFound);
    }

    log_debug!("Checking cache for directory: {:?}", &normalized_requested);
    if let Some(mut cache_entry) = data.meta_cache.get_async(&normalized_requested).await {
        let (cached_dir_meta, timestamp) = cache_entry.get();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if now - timestamp < CACHE_TTL_SECONDS {
            data.cache_stats.increment_hits();
            log_debug!("Cache hit for directory: {:?}", &normalized_requested);
            let dir_ents = cached_dir_meta.get_all_entries_serialized();
            return Ok(actix_web::HttpResponse::Ok().body(actix_web::web::Bytes::from(dir_ents)));
        }

        log_debug!("Expired cache entry: {:?}", &normalized_requested);
        data.cache_stats.increment_misses();
        let directory_entry = &create_meta_cache_entry(cache_entry.key().to_owned()).await?;
        cache_entry.put((directory_entry.clone(), now));
        let dir_ents = directory_entry.get_all_entries_serialized();
        return Ok(actix_web::HttpResponse::Ok().body(actix_web::web::Bytes::from(dir_ents)));
    }

    data.cache_stats.increment_misses();

    let directory_entry = &create_meta_cache_entry(normalized_requested.clone()).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    data.meta_cache
        .put(normalized_requested, (directory_entry.clone(), now))
        .map_err(|_| {
            log_warn!("Failed to insert entry into cache");
            AppError::Internal(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Cache insertion failed",
            ))
        })?;

    let dir_ents = directory_entry.get_all_entries_serialized();
    Ok(actix_web::HttpResponse::Ok().body(actix_web::web::Bytes::from(dir_ents)))
}

async fn read_file_buffer_handler(
    data: actix_web::web::Data<AppState>,
    params: actix_web::web::Query<FileRequest>,
) -> Result<actix_files::NamedFile, AppError> {
    log_info!("[FILE READ] Handling request for: {}", &params.file_path);

    let normalized_requested = validate_path(&data.base_path, &params.file_path)?;
    log_debug!(
        "Serving file from validated path: {:?}",
        &normalized_requested
    );

    let canonicalized_path = tokio::fs::canonicalize(&normalized_requested).await?;

    if !canonicalized_path.starts_with(&data.base_path) {
        return Err(AppError::PathTraversal);
    }

    actix_files::NamedFile::open_async(&normalized_requested)
        .await
        .map_err(|e| {
            log_warn!("Failed to open file {:?}: {}", &normalized_requested, e);
            AppError::Internal(e)
        })
}

#[actix_web::main]
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

    let state = actix_web::web::Data::new(AppState {
        meta_cache: scc::HashCache::with_capacity(1000, 20000),
        base_path: path.clone(),
        cache_stats: utils::stats::Cache::new(),
    });

    #[cfg(feature = "stats")]
    start_cache_statistics_logger(state.clone());

    log_info!("Starting server on port {} serving path: {:?}", port, &path);
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(actix_web::middleware::Logger::new("%a %{User-Agent}i").exclude("/healthcheck"))
            .app_data(state.clone())
            .service(
                actix_web::web::resource("/get_file_info")
                    .route(actix_web::web::get().to(get_file_info_handler)),
            )
            .service(
                actix_web::web::resource("/get_dir_info")
                    .route(actix_web::web::get().to(get_dir_info_handler)),
            )
            .service(
                actix_web::web::resource("/get_file")
                    .route(actix_web::web::get().to(read_file_buffer_handler)),
            )
            .service(actix_web::web::resource("/healthcheck").route(
                actix_web::web::get().to(|| async { actix_web::HttpResponse::Ok().body("OK") }),
            ))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

#[cfg(feature = "stats")]
fn start_cache_statistics_logger(state: actix_web::web::Data<AppState>) {
    const STATS_LOG_INTERVAL_SECONDS: u64 = 30;

    actix_web::rt::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(STATS_LOG_INTERVAL_SECONDS));
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
    use actix_web::{http, test, web, App};
    use generated::blorg_meta_flat::{Directory, DirectoryEntryMetadata};
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;

    // Test setup helper
    async fn setup_test_env() -> (PathBuf, web::Data<AppState>) {
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

        let state = web::Data::new(AppState {
            meta_cache: scc::HashCache::with_capacity(1000, 20000),
            base_path: base_dir.clone(),
            cache_stats: utils::stats::Cache::new(),
        });

        (base_dir, state)
    }

    #[actix_web::test]
    async fn test_valid_file_info() {
        let (_temp_dir, state) = setup_test_env().await;

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file_info").to(get_file_info_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/get_file_info?file_path=test_file.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;

        // Parse FlatBuffer data
        let fb_data: DirectoryEntryMetadata =
            flatbuffers::root::<DirectoryEntryMetadata>(&body).unwrap();

        assert_eq!(fb_data.name(), "test_file.txt");
        assert_eq!(fb_data.size(), 12);
    }

    #[actix_web::test]
    async fn test_nonexistent_file_info() {
        let (_temp_dir, state) = setup_test_env().await;

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file_info").to(get_file_info_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/get_file_info?file_path=nonexistent.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn test_directory_info() {
        let (_temp_dir, state) = setup_test_env().await;

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_dir_info").to(get_dir_info_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/get_dir_info?directory=test_dir")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;

        // Parse FlatBuffer data
        let fb_data: Directory = flatbuffers::root::<Directory>(&body).unwrap();

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

    #[actix_web::test]
    async fn test_file_download() {
        let (_temp_dir, state) = setup_test_env().await;

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file").to(read_file_buffer_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/get_file?file_path=test_file.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = test::read_body(resp).await;
        assert_eq!(body, "test content");
    }

    #[actix_web::test]
    async fn test_path_traversal_protection_posix() {
        let (_temp_dir, state) = setup_test_env().await;

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file_info").to(read_file_buffer_handler)),
        )
        .await;

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=../passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=/../passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=test_dir/../../passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=test_dir/../")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=./test_dir/../")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=test_dir/./../")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }
    }

    #[actix_web::test]
    async fn test_path_traversal_protection_windows() {
        let (_temp_dir, state) = setup_test_env().await;

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file_info").to(read_file_buffer_handler)),
        )
        .await;

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=..\\passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=\\..\\passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=test_dir\\..\\..\\passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=test_dir\\..\\")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=.\\test_dir\\..\\")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file_info?file_path=test_dir\\.\\..\\")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }
    }

    #[cfg(feature = "stats")]
    #[actix_web::test]
    async fn test_cache_behavior() {
        let (_temp_dir, state) = setup_test_env().await;

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_dir_info").to(get_dir_info_handler)),
        )
        .await;

        // First request (cache miss)
        let req = test::TestRequest::get()
            .uri("/get_dir_info?directory=test_dir")
            .to_request();
        let _ = test::call_service(&app, req).await;
        assert_eq!(state.cache_stats.get().0, 0);
        assert_eq!(state.cache_stats.get().1, 1);

        // Second request (cache hit)
        let req = test::TestRequest::get()
            .uri("/get_dir_info?directory=test_dir")
            .to_request();
        let _ = test::call_service(&app, req).await;
        assert_eq!(state.cache_stats.get().0, 1);
        assert_eq!(state.cache_stats.get().1, 1);
    }

    #[cfg(feature = "stats")]
    #[actix_web::test]
    async fn test_cache_expiration() {
        let (_temp_dir, state) = setup_test_env().await;

        // Manually insert an expired cache entry
        let path = state.base_path.join("test_dir");
        let old_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - CACHE_TTL_SECONDS
            - 1;

        state
            .meta_cache
            .put(
                path.clone(),
                (
                    utils::cache::metadata::DirectoryLookupContext::new(),
                    old_time,
                ),
            )
            .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_dir_info").to(get_dir_info_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/get_dir_info?directory=test_dir")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        // Verify cache was updated
        assert_eq!(state.cache_stats.get().1, 1); // Should count as miss
    }

    #[actix_web::test]
    async fn test_deep_nested_directories() {
        let (temp_dir, state) = setup_test_env().await;
        let mut path = temp_dir.clone();
        for depth in 0..10 {
            path = path.join(format!("level_{}", depth));
            fs::create_dir(&path).unwrap();
        }
        File::create(path.join("deep_file.txt")).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file_info").to(get_file_info_handler)),
        )
        .await;

        let req = test::TestRequest::get()
        .uri("/get_file_info?file_path=level_0/level_1/level_2/level_3/level_4/level_5/level_6/level_7/level_8/level_9/deep_file.txt")
        .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_permission_denied() {
        let (temp_dir, state) = setup_test_env().await;
        let restricted_dir = temp_dir.join("restricted");
        fs::create_dir(&restricted_dir).unwrap();
        let restricted_file = restricted_dir.join("no_access.txt");
        File::create(&restricted_file).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o000)).unwrap();
        }

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_dir_info").to(get_dir_info_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/get_dir_info?directory=restricted")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);

        #[cfg(unix)]
        fs::set_permissions(
            restricted_dir,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .unwrap();
    }

    #[actix_web::test]
    async fn test_cache_invalidation_after_modification() {
        let (temp_dir, state) = setup_test_env().await;
        let file_path = temp_dir.join("modifiable.txt");
        File::create(&file_path).unwrap().write_all(b"v1").unwrap();

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file_info").to(get_file_info_handler)),
        )
        .await;

        // Initial request to populate cache
        let req = test::TestRequest::get()
            .uri("/get_file_info?file_path=modifiable.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;

        let body = test::read_body(resp).await;

        let fb_data: DirectoryEntryMetadata =
            flatbuffers::root::<DirectoryEntryMetadata>(&body).unwrap();

        assert_eq!(fb_data.size(), 2);

        // Modify the file
        File::create(&file_path)
            .unwrap()
            .write_all(b"updated")
            .unwrap();

        // Fast-forward time beyond TTL
        if let Some(mut foo) = state.meta_cache.get_async(&temp_dir).await {
            let bar = foo.get_mut();
            bar.1 = 0; // Set timestamp to epoch to simulate expiration
        }
        // Subsequent request should fetch fresh data
        let req = test::TestRequest::get()
            .uri("/get_file_info?file_path=modifiable.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;

        let body = test::read_body(resp).await;

        let fb_data: DirectoryEntryMetadata =
            flatbuffers::root::<DirectoryEntryMetadata>(&body).unwrap();

        assert_eq!(fb_data.size(), 7);
    }

    #[actix_web::test]
    async fn test_concurrent_cache_access() {
        // needs some code
        let (_temp_dir, state) = setup_test_env().await;
        let service = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_dir_info").to(get_dir_info_handler)),
        )
        .await;

        let mut results = vec![];

        for _ in 0..100000 {
            let req = test::TestRequest::get()
                .uri("/get_dir_info?directory=test_dir")
                .to_request();
            results.push(test::call_service(&service, req).await.status());
        }

        for result in results {
            assert_eq!(result, http::StatusCode::OK);
        }

        // Ensure cache stats reflect the concurrent hits/misses appropriately
        #[cfg(feature = "stats")]
        assert_eq!(state.cache_stats.get().0, 99999); // 1 miss + 99999 hits
    }

    #[actix_web::test]
    async fn test_special_char_filenames() {
        let (temp_dir, state) = setup_test_env().await;
        let file_names = vec!["файл.txt", "スペース ファイル", "😀.md"];

        for name in &file_names {
            File::create(temp_dir.join(name)).unwrap();
        }

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_dir_info").to(get_dir_info_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/get_dir_info?directory=.")
            .to_request();
        let resp = test::call_service(&app, req).await;

        let body = test::read_body(resp).await;

        let fb_data: Directory = flatbuffers::root::<Directory>(&body).unwrap();
        let entries = fb_data.files().unwrap().name().unwrap();

        for name in file_names {
            assert!(entries.iter().any(|e| e == name));
        }
    }

    #[actix_web::test]
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

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file").to(read_file_buffer_handler)),
        )
        .await;

        // Test valid symlink
        let req = test::TestRequest::get()
            .uri("/get_file?file_path=valid_link.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = test::read_body(resp).await;
        assert_eq!(body, "valid content");

        // Test malicious symlink
        let req = test::TestRequest::get()
            .uri("/get_file?file_path=malicious_link.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        let body = test::read_body(resp).await;
        assert_eq!(body, "Path traversal attempt detected");
    }

    #[actix_web::test]
    async fn test_file_and_data_changes() {
        let (temp_dir, state) = setup_test_env().await;
        let file_path = temp_dir.join("modifiable.txt");
        File::create(&file_path).unwrap().write_all(b"v1").unwrap();

        // obtain file metadata like creation time
        let metadata = fs::metadata(&file_path).unwrap();

        let created_secs =
            crate::utils::windows::time::IntoFileTime::into_file_time(metadata.created().unwrap());

        let modified_secs =
            crate::utils::windows::time::IntoFileTime::into_file_time(metadata.modified().unwrap());

        let accessed_secs =
            crate::utils::windows::time::IntoFileTime::into_file_time(metadata.accessed().unwrap());

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::resource("/get_file_info").to(get_file_info_handler)),
        )
        .await;

        // Initial request to populate cache
        let req = test::TestRequest::get()
            .uri("/get_file_info?file_path=modifiable.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;

        let body = test::read_body(resp).await;

        let fb_data: DirectoryEntryMetadata =
            flatbuffers::root::<DirectoryEntryMetadata>(&body).unwrap();

        assert_eq!(fb_data.name(), "modifiable.txt");
        assert_eq!(fb_data.size(), metadata.len());
        assert_eq!(fb_data.created(), created_secs);
        assert_eq!(fb_data.modified(), modified_secs);
        assert_eq!(fb_data.accessed(), accessed_secs);

        // Modify the file
        File::create(&file_path)
            .unwrap()
            .write_all(b"updated")
            .unwrap();

        // Fast-forward time beyond TTL
        if let Some(mut foo) = state.meta_cache.get_async(&temp_dir).await {
            let bar = foo.get_mut();
            bar.1 = 0; // Set timestamp to epoch to simulate expiration
        }
        // Subsequent request should fetch fresh data
        let req = test::TestRequest::get()
            .uri("/get_file_info?file_path=modifiable.txt")
            .to_request();
        let resp = test::call_service(&app, req).await;

        let body = test::read_body(resp).await;

        let fb_data: DirectoryEntryMetadata =
            flatbuffers::root::<DirectoryEntryMetadata>(&body).unwrap();

        assert_eq!(fb_data.name(), "modifiable.txt");
        assert_eq!(fb_data.size(), 7);
        assert_eq!(fb_data.created(), created_secs);
    }
}
