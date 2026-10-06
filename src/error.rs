//! The one error type every layer of the server speaks.
//!
//! It deliberately carries no payload. `moka`'s single-flight loaders hand
//! every waiter an `Arc<E>` when a coalesced load fails, so keeping this `Copy`
//! lets each waiter take the value out for free instead of cloning boxed state.

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AppError {
    #[error("Path traversal attempt detected")]
    PathTraversal,
    #[error("Resource not found")]
    NotFound,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Internal server error")]
    Internal,
    #[error("Missing or malformed request")]
    BadRequest,
    #[error("Change feed is not running")]
    FeedUnavailable,
    #[error("The name is taken, or the directory is not empty")]
    Conflict,
    #[error("The entry is no longer the version the request names")]
    PreconditionFailed,
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty => {
                Self::Conflict
            }
            _ => Self::Internal,
        }
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(_: tokio::task::JoinError) -> Self {
        Self::Internal
    }
}

/// Unwraps the `Arc` that `moka`'s `try_get_with` returns to every waiter of a
/// failed coalesced load.
impl From<std::sync::Arc<Self>> for AppError {
    fn from(error: std::sync::Arc<Self>) -> Self {
        *error
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        crate::log_error!("API error: {self}");

        let status = match self {
            Self::PermissionDenied | Self::PathTraversal => axum::http::StatusCode::FORBIDDEN,
            Self::NotFound => axum::http::StatusCode::NOT_FOUND,
            Self::Internal => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest => axum::http::StatusCode::BAD_REQUEST,
            Self::FeedUnavailable => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::Conflict => axum::http::StatusCode::CONFLICT,
            Self::PreconditionFailed => axum::http::StatusCode::PRECONDITION_FAILED,
        };

        axum::response::IntoResponse::into_response(status)
    }
}
