//! PostgreSQL database connection module
//! Handle PostgreSQL-specific connection pool creation and management

use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::time::Duration;
use log::info;
use crate::config::DbConfig;
use crate::DbError;

/// Create PostgreSQL database connection
pub(crate) async fn create_postgresql_connection(config: &DbConfig) -> Result<DatabaseConnection, DbError> {
    info!("Configuring PostgreSQL connection parameters: url={}, timeout={}s", config.url, config.timeout);
    let mut opt = ConnectOptions::new(config.url.clone());
    opt.max_connections(config.max_connections)
       .connect_timeout(Duration::from_secs(config.timeout)).sqlx_logging(false);
    info!("PostgreSQL connection parameters configured, establishing connection...");

    Database::connect(opt)
        .await
        .map_err(|e| DbError::ConnectionError(e.to_string()))
}