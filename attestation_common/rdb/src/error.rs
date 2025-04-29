//! Database error handling module
//! Define custom error types for database operations

use thiserror::Error;

/// Database operation error
#[derive(Error, Debug, Clone)]
pub enum DbError {
    /// Database URL not provided in environment variables
    #[error("Database URL is not provided in environment variables")]
    MissingDatabaseUrl,

    /// Invalid database type specified
    #[error("Invalid database type: {0}")]
    InvalidDatabaseType(String),

    /// Database connection error
    #[error("Failed to connect to database: {0}")]
    ConnectionError(String),

    /// Database connection pool initialization error
    #[error("Failed to initialize connection pool: {0}")]
    PoolError(String),

    /// General database error
    #[error("Database error: {0}")]
    Other(String),
}

impl From<sea_orm::DbErr> for DbError {
    fn from(err: sea_orm::DbErr) -> Self {
        DbError::Other(err.to_string())
    }
}