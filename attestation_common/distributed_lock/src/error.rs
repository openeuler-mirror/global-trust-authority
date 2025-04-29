
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DistributedLockError {
    #[error("Redis operation failed: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("Lock acquisition timeout")]
    AcquireTimeout,

    #[error("Lock does not exist or has expired")]
    LockNotExists,

    #[error("No permission to operate this lock")]
    InvalidLockOwner,

    #[error("Parameter error: {0}")]
    InvalidArgument(String),
}

pub type Result<T> = std::result::Result<T, DistributedLockError>;