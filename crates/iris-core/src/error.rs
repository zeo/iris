use thiserror::Error;

/// errors surfaced by a platform engine implementation
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine not initialized")]
    NotInitialized,
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("os call failed: {0}")]
    Os(String),
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Other(String),
}

pub type EngineResult<T> = Result<T, EngineError>;
