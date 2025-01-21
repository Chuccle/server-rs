// main.rs
use actix_web::{web, App, HttpResponse, HttpServer, ResponseError};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use utils::cache::metadata::DirectoryLookupContext;

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

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        log::error!("API error: {}", self);
        match self {
            AppError::PathTraversal => HttpResponse::Forbidden().body(self.to_string()),
            AppError::InvalidPathEncoding | AppError::InvalidPath => {
                HttpResponse::BadRequest().body(self.to_string())
            }
            AppError::NotFound => HttpResponse::NotFound().body(self.to_string()),
            _ => HttpResponse::InternalServerError().body("Internal Server Error"),
        }
    }
}

#[derive(Deserialize)]
struct FileQuery {
    file_path: String,
}

#[derive(Deserialize)]
struct DirQuery {
    directory: String,
}

#[derive(Deserialize)]
struct FileRequest {
    file_path: String,
}

struct AppState {
    meta_cache: scc::HashCache<PathBuf, (DirectoryLookupContext, u64)>,
    base_path: String,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

const CACHE_TTL_SECONDS: u64 = 300;
const STATS_LOG_INTERVAL_SECONDS: u64 = 30;

async fn validate_path(base: &str, requested_path: &str) -> Result<PathBuf, AppError> {
    let base_dir = PathBuf::from(base);
    let canonical_base = base_dir.canonicalize()?;

    let requested = base_dir.join(requested_path);
    let canonical_requested = requested.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(e)
        }
    })?;

    if !canonical_requested.starts_with(&canonical_base) {
        Err(AppError::PathTraversal)
    } else {
        Ok(canonical_requested)
    }
}

async fn get_file_info_handler(
    data: web::Data<AppState>,
    params: web::Query<FileQuery>,
) -> Result<HttpResponse, AppError> {
    log::info!("get_file_info_handler - {}", &params.file_path);

    let canonical_requested = validate_path(&data.base_path, &params.file_path).await?;

    if !canonical_requested.is_file() {
        return Err(AppError::NotFound);
    }

    let parent_dir = canonical_requested.parent().ok_or(AppError::InvalidPath)?;

    if let Some(entry) = data.meta_cache.get_async(parent_dir).await {
        let (cached_meta, timestamp) = entry.get();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if now - timestamp < CACHE_TTL_SECONDS {
            data.cache_hits.fetch_add(1, Ordering::Relaxed);
            let file_name = canonical_requested
                .file_name()
                .ok_or(AppError::InvalidPath)?
                .to_str()
                .ok_or(AppError::InvalidPathEncoding)?;

            if let Some(dir_ent) = cached_meta.get_file(file_name) {
                return Ok(HttpResponse::Ok().json(dir_ent));
            }
        } else {
            data.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        data.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    let meta = tokio::fs::metadata(&canonical_requested).await?;
    let file_name = canonical_requested
        .file_name()
        .ok_or(AppError::InvalidPath)?
        .to_str()
        .ok_or(AppError::InvalidPathEncoding)?;

    let file_entry = utils::cache::metadata::create_direntmeta(&meta, file_name).map_err(|_| {
        AppError::Internal(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to create directory entry",
        ))
    })?;

    Ok(HttpResponse::Ok().json(file_entry))
}

async fn get_dir_info_handler(
    data: web::Data<AppState>,
    params: web::Query<DirQuery>,
) -> Result<HttpResponse, AppError> {
    log::info!("get_dir_info_handler - {}", &params.directory);

    let canonical_requested = validate_path(&data.base_path, &params.directory).await?;

    if !canonical_requested.is_dir() {
        return Err(AppError::NotFound);
    }

    if let Some(entry) = data.meta_cache.get_async(&canonical_requested).await {
        let (cached_meta, timestamp) = entry.get();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if now - timestamp < CACHE_TTL_SECONDS {
            data.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(HttpResponse::Ok().json(&cached_meta.get_all_entries().collect::<Vec<_>>()));
        } else {
            data.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        data.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    let entry = tokio::task::spawn_blocking({
        let path = canonical_requested.clone();
        let data = data.clone();
        move || -> Result<_, AppError> {
            let mut cache_entry = DirectoryLookupContext::new();
            let dir = std::fs::read_dir(&path)?;

            for entry_result in dir {
                let entry = entry_result?;
                let name = entry.file_name().into_string().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid filename encoding",
                    )
                })?;

                let metadata = entry.metadata()?;
                let direntmeta = utils::cache::metadata::create_direntmeta(&metadata, &name)?;

                if metadata.is_dir() {
                    cache_entry.add_subdir(direntmeta);
                } else {
                    cache_entry.add_file(direntmeta);
                }
            }

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let _ = data.meta_cache.put(path, (cache_entry.clone(), now));

            Ok(cache_entry)
        }
    })
    .await??;

    Ok(HttpResponse::Ok().json(&entry.get_all_entries().collect::<Vec<_>>()))
}

async fn read_file_buffer_handler(
    data: web::Data<AppState>,
    params: web::Query<FileRequest>,
) -> Result<actix_files::NamedFile, AppError> {
    log::info!("read_file_buffer_handler - {}", &params.file_path);

    let canonical_requested = validate_path(&data.base_path, &params.file_path).await?;
    Ok(actix_files::NamedFile::open_async(&canonical_requested).await?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!(
            "Usage: {} <directory-path>",
            std::env::args().next().unwrap()
        );
        std::process::exit(1);
    });

    // New base path validation
    let base_path = std::path::Path::new(&path);
    if !base_path.exists() {
        eprintln!("Error: Provided path '{}' does not exist", path);
        std::process::exit(1);
    }
    if !base_path.is_dir() {
        eprintln!("Error: Provided path '{}' is not a directory", path);
        std::process::exit(1);
    }

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let state = web::Data::new(AppState {
        meta_cache: scc::HashCache::with_capacity(1000, 20000),
        base_path: path.clone(),
        cache_hits: AtomicU64::new(0),
        cache_misses: AtomicU64::new(0),
    });

    // Start statistics logging task
    let logging_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(STATS_LOG_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            let hits = logging_state.cache_hits.load(Ordering::Relaxed);
            let misses = logging_state.cache_misses.load(Ordering::Relaxed);
            let total = hits + misses;
            let hit_rate = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            log::info!(
                "Cache Statistics: Hits={}, Misses={}, Hit Rate={:.2}%, Total Requests={}",
                hits,
                misses,
                hit_rate,
                total
            );
        }
    });

    HttpServer::new(move || {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .app_data(state.clone())
            .service(web::resource("/get_file_info").route(web::get().to(get_file_info_handler)))
            .service(web::resource("/get_dir_info").route(web::get().to(get_dir_info_handler)))
            .service(web::resource("/get_file").route(web::get().to(read_file_buffer_handler)))
            .service(actix_files::Files::new("/repo", &path))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
