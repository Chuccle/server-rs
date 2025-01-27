mod utils;

// TODO:
// We need to use inotify for cache invalidation, we can then remove timestamp coupled to each entry
// We should probably introduce some more sophisticated tests

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
}

impl actix_web::ResponseError for AppError {
    fn error_response(&self) -> actix_web::HttpResponse {
        log_error!("API error: {}", self);
        match self {
            AppError::PathTraversal => actix_web::HttpResponse::Forbidden().body(self.to_string()),
            AppError::InvalidPathEncoding | AppError::InvalidPath => {
                actix_web::HttpResponse::BadRequest().body(self.to_string())
            }
            AppError::NotFound => actix_web::HttpResponse::NotFound().body(self.to_string()),
            _ => actix_web::HttpResponse::NotFound().body("Resource not found"),
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
    cache_stats: utils::stats::CacheStats,
}

const CACHE_TTL_SECONDS: u64 = 300;

async fn dedotify_path(path: &str) -> Result<Option<String>, AppError> {
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

async fn validate_path(
    base_dir: &std::path::Path,
    requested_path: &str,
) -> Result<std::path::PathBuf, AppError> {
    log_debug!(
        "Starting path validation for '{}' in base_dir '{:?}'",
        requested_path,
        base_dir
    );

    let requested = dedotify_path(&requested_path.replace('\\', "/")).await?;

    match requested {
        Some(requested) => Ok(base_dir.join(requested)),
        None => Ok(base_dir.to_owned()),
    }
}

async fn get_file_info_handler(
    data: actix_web::web::Data<AppState>,
    params: actix_web::web::Query<FileQuery>,
) -> Result<actix_web::HttpResponse, AppError> {
    log_info!("[FILE INFO] Handling request for: {}", &params.file_path);

    let canonical_requested = validate_path(&data.base_path, &params.file_path).await?;
    log_trace!("Validated canonical path: {:?}", &canonical_requested);

    if !canonical_requested.is_file() {
        log_debug!("Path is not a file: {:?}", &canonical_requested);
        return Err(AppError::NotFound);
    }

    let parent_dir = canonical_requested.parent().ok_or_else(|| {
        log_warn!("Invalid file path structure: {:?}", &canonical_requested);
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

            let file_name = canonical_requested
                .file_name()
                .ok_or(AppError::InvalidPath)?
                .to_str()
                .ok_or(AppError::InvalidPathEncoding)?;

            log_trace!("Looking for file in cache: {}", file_name);
            if let Some(dir_ent) = cached_meta.get_file(file_name) {
                log_debug!("File found in cache: {}", file_name);
                return Ok(actix_web::HttpResponse::Ok().json(dir_ent));
            }
        } else {
            log_debug!("Cache entry expired for: {:?}", parent_dir);
            data.cache_stats.increment_misses();
        }
    } else {
        log_debug!("Cache miss for directory: {:?}", parent_dir);
        data.cache_stats.increment_misses();
    }

    log_info!("Fetching fresh metadata for: {:?}", &canonical_requested);
    let meta = tokio::fs::symlink_metadata(&canonical_requested)
        .await
        .map_err(|e| {
            log_warn!(
                "Metadata fetch failed for {:?}: {}",
                &canonical_requested,
                e
            );
            AppError::Internal(e)
        })?;

    let file_name = canonical_requested
        .file_name()
        .ok_or(AppError::InvalidPath)?
        .to_str()
        .ok_or(AppError::InvalidPathEncoding)?;

    let file_entry = utils::cache::metadata::create_direntmeta(&meta, file_name).map_err(|e| {
        log_error_with_context!(e, "Failed to create directory entry for {}", file_name);
        AppError::Internal(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to create directory entry",
        ))
    })?;

    Ok(actix_web::HttpResponse::Ok().json(&file_entry))
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

                        let name = if let Ok(name) = entry.file_name().into_string() {
                            name
                        } else {
                            log_debug!("Invalid filename encoding: {:?}", &entry.path());
                            continue;
                        };

                        match entry.metadata() {
                            Ok(metadata) => {
                                match utils::cache::metadata::create_direntmeta(&metadata, &name) {
                                    Ok(direntmeta) => {
                                        if metadata.is_dir() {
                                            cache_entry.add_subdir(direntmeta);
                                        } else {
                                            cache_entry.add_file(direntmeta);
                                        }
                                    }
                                    Err(e) => {
                                        log_debug_with_context!(
                                            e,
                                            "Failed to create direntmeta for {}",
                                            &name
                                        );
                                    }
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

    let canonical_requested = validate_path(&data.base_path, &params.directory).await?;
    log_trace!("Validated canonical path: {:?}", &canonical_requested);

    if !canonical_requested.is_dir() {
        log_debug!("Path is not a directory: {:?}", &canonical_requested);
        return Err(AppError::NotFound);
    }

    log_debug!("Checking cache for directory: {:?}", &canonical_requested);
    if let Some(mut entry) = data.meta_cache.get_async(&canonical_requested).await {
        let (cached_meta, timestamp) = entry.get();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if now - timestamp < CACHE_TTL_SECONDS {
            data.cache_stats.increment_hits();
            log_debug!("Cache hit for directory: {:?}", &canonical_requested);
            return Ok(actix_web::HttpResponse::Ok()
                .json(cached_meta.get_all_entries().collect::<Vec<_>>()));
        } else {
            log_debug!("Expired cache entry: {:?}", &canonical_requested);
            data.cache_stats.increment_misses();
            let directory_entry = &create_meta_cache_entry(entry.key().to_owned()).await?;
            entry.put((directory_entry.clone(), now));
            return Ok(actix_web::HttpResponse::Ok()
                .json(directory_entry.get_all_entries().collect::<Vec<_>>()));
        }
    }

    data.cache_stats.increment_misses();

    let directory_entry = &create_meta_cache_entry(canonical_requested.to_owned()).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    data.meta_cache
        .put(canonical_requested, (directory_entry.clone(), now))
        .map_err(|_| {
            log_warn!("Failed to insert entry into cache");
            AppError::Internal(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Cache insertion failed",
            ))
        })?;

    Ok(actix_web::HttpResponse::Ok().json(directory_entry.get_all_entries().collect::<Vec<_>>()))
}

async fn read_file_buffer_handler(
    data: actix_web::web::Data<AppState>,
    params: actix_web::web::Query<FileRequest>,
) -> Result<actix_files::NamedFile, AppError> {
    log_info!("[FILE READ] Handling request for: {}", &params.file_path);

    let canonical_requested = validate_path(&data.base_path, &params.file_path).await?;
    log_debug!(
        "Serving file from validated path: {:?}",
        &canonical_requested
    );

    actix_files::NamedFile::open_async(&canonical_requested)
        .await
        .map_err(|e| {
            log_warn!("Failed to open file {:?}: {}", &canonical_requested, e);
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
            std::env::args().next().unwrap_or("server-rs".to_owned())
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
        cache_stats: utils::stats::CacheStats::new(),
    });

    #[cfg(feature = "cache_stats")]
    start_cache_stat_logger(state.clone());

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
            .service(actix_files::Files::new("/repo", &path))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

#[cfg(feature = "cache_stats")]
fn start_cache_stat_logger(state: actix_web::web::Data<AppState>) {
    const STATS_LOG_INTERVAL_SECONDS: u64 = 30;

    actix_web::rt::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(STATS_LOG_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            let (hits, misses) = state.cache_stats.get_stats();
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
            cache_stats: utils::stats::CacheStats::new(),
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
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["name"], "test_file.txt");
        assert_eq!(body["size"], 12);
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
        let body: Vec<serde_json::Value> = test::read_body_json(resp).await;
        assert!(!body.is_empty());
        assert_eq!(body[0]["info"]["name"], "file_in_dir.txt");
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
                .service(web::resource("/get_file").to(read_file_buffer_handler)),
        )
        .await;

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=../passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=/../passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=test_dir/../../passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=test_dir/../")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=./test_dir/../")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=test_dir/./../")
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
                .service(web::resource("/get_file").to(read_file_buffer_handler)),
        )
        .await;

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=..\\passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=\\..\\passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=test_dir\\..\\..\\passwd.txt")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=test_dir\\..\\")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=.\\test_dir\\..\\")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }

        {
            let req = test::TestRequest::get()
                .uri("/get_file?file_path=test_dir\\.\\..\\")
                .to_request();
            let resp = test::call_service(&app, req).await;

            assert_eq!(resp.status(), http::StatusCode::OK);
        }
    }

    #[cfg(feature = "cache_stats")]
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
        assert_eq!(state.cache_stats.get_stats().0, 0);
        assert_eq!(state.cache_stats.get_stats().1, 1);

        // Second request (cache hit)
        let req = test::TestRequest::get()
            .uri("/get_dir_info?directory=test_dir")
            .to_request();
        let _ = test::call_service(&app, req).await;
        assert_eq!(state.cache_stats.get_stats().0, 1);
        assert_eq!(state.cache_stats.get_stats().1, 1);
    }

    #[cfg(feature = "cache_stats")]
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
        assert_eq!(state.cache_stats.get_stats().1, 1); // Should count as miss
    }
}
