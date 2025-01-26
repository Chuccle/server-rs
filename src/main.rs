mod utils;

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
            _ => actix_web::HttpResponse::InternalServerError().body("Internal Server Error"),
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

async fn validate_path(
    base_dir: &std::path::Path,
    requested_path: &str,
) -> Result<std::path::PathBuf, AppError> {
    log_debug!(
        "Starting path validation for '{}' in base_dir '{:?}'",
        requested_path,
        base_dir
    );

    let requested = base_dir.join(requested_path);
    log_trace!("Constructed full requested path: {:?}", &requested);

    let canonical_requested = requested.canonicalize().map_err(|e| {
        log_debug!("Path resolution failed for '{}': {}", requested_path, e);
        if let std::io::ErrorKind::NotFound = e.kind() {
            log_info!("Path not found: '{}'", requested_path);
            AppError::NotFound
        } else {
            log_warn!(
                "Unexpected error resolving path '{}': {}",
                requested_path,
                e
            );
            AppError::Internal(e)
        }
    })?;

    log_debug!(
        "Path resolution complete - Requested: {:?}",
        &canonical_requested
    );

    if !canonical_requested.starts_with(base_dir) {
        log_warn!(
            "Path traversal attempt! Base: {:?}, Attempted: {:?}",
            &base_dir,
            &canonical_requested
        );
        Err(AppError::PathTraversal)
    } else {
        log_trace!("Path validation successful for {:?}", &canonical_requested);
        Ok(canonical_requested)
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
    if let Some(entry) = data.meta_cache.get_async(&canonical_requested).await {
        let (cached_meta, timestamp) = entry.get();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if now - timestamp < CACHE_TTL_SECONDS {
            data.cache_stats.increment_hits();
            log_debug!("Cache hit for directory: {:?}", &canonical_requested);
            return Ok(actix_web::HttpResponse::Ok()
                .json(cached_meta.get_all_entries().collect::<Vec<_>>()));
        }
    }

    data.cache_stats.increment_misses();
    log_debug!(
        "Building new cache entry for directory: {:?}",
        &canonical_requested
    );

    let entry = tokio::task::spawn_blocking({
        let path = canonical_requested.clone();
        let data = data.clone();
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

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();

            data.meta_cache
                .put(path, (cache_entry.clone(), now))
                .map_err(|_| {
                    log_warn!("Failed to insert entry into cache");
                    AppError::Internal(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Cache insertion failed",
                    ))
                })?;

            Ok(cache_entry)
        }
    })
    .await
    .map_err(|e| {
        log_error!("Directory processing task failed: {}", e);
        AppError::TaskJoin(e)
    })??;

    Ok(actix_web::HttpResponse::Ok().json(entry.get_all_entries().collect::<Vec<_>>()))
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
