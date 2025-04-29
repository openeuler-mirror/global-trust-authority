use thiserror::Error;

#[derive(Debug, Error)]
pub enum RedisError {
    #[error("Redis connect error: {0}")]
    ConnectionError(#[from] redis::RedisError),

    #[error("Redis key not exist")]
    KeyNotFound,

    #[error("Redis value serialization error value serialization error: {0}")]
    SerializationError(String),

    #[error("Redis value deserialization error: {0}")]
    DeserializationError(String),

    #[error("Redis operation error: {0}")]
    OperationError(String),
}