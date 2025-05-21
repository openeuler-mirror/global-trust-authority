//! Database Configuration Module
//! Handles environment variables and connection settings

use std::env;
use log::{info, error};
use env_config_parse::find_file;
use crate::DbError;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Database type ("mysql" or "postgresql")
    pub db_type: String,
    /// Database connection URL
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Connection timeout (seconds)
    pub timeout: u64,
}

impl DbConfig {
    /// get env
    pub fn from_env() -> Result<Self, DbError> {
        info!("get db config from env");
        #[cfg(debug_assertions)]
        {
            dotenv::dotenv().ok().map(|_| std::env::vars().for_each(|(k, _)| std::env::remove_var(&k)));
            let file_path = find_file(".env.dev").map(|p| p.to_str().unwrap().to_string()).unwrap();
            dotenv::from_filename(file_path).expect("Failed to load .env.dev");
        }
        let mut db_type = env::var("DB_TYPE").expect("DB_TYPE must be set");
        db_type = db_type.to_lowercase();
        let url = match db_type.as_str() {
            "mysql" => {
                info!("db type is mysql");
                dbg!(env::var("MYSQL_DATABASE_URL"));
                env::var("MYSQL_DATABASE_URL").expect("MYSQL_DATABASE_URL must be set")}
            "postgres" => {
                info!("db type is postgresql");
                env::var("POSTGRESQL_DATABASE_URL").expect("POSTGRESQL_DATABASE_URL must be set")}
            _ => {
                error!("db type is not support");
                return Err(DbError::InvalidDatabaseType(db_type));
            }
        };
        // Get optional configuration with defaults
        let max_connections = env::var("DATABASE_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        let timeout = env::var("DATABASE_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        Ok(Self {
            db_type,
            url,
            max_connections,
            timeout,
        })
    }
}