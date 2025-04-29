//! Database connection management module
//! Provides unified connection pool management for MySQL and PostgreSQL

pub mod config;
pub mod error;
pub mod rdb_many_types {
    pub mod postgresql;
    pub mod mysql;
}
pub mod connection;

pub use error::DbError;
pub use connection::get_connection;
pub use connection::execute_sql_file;