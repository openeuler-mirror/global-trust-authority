//! Database Connection Management Module
//! Provides unified database connection pool management functionality

use std::error::Error;
use std::path::PathBuf;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement, TransactionTrait};
use std::sync::Arc;
use tokio::sync::OnceCell;
use dotenv::dotenv;
use log::{info, error};
use env_config_parse::find_file;
use crate::config::DbConfig;
use crate::DbError;
use crate::rdb_many_types::{mysql, postgresql};

/// database info
static DB_CONN: OnceCell<Arc<DatabaseConnection>> = OnceCell::const_new();

/// Get database connection
/// 
/// Returns a reference to the database connection. The connection is initialized on first call,
/// subsequent calls will reuse the same connection.
/// 
/// # Example
/// ```rust
/// use rdb::get_connection;
/// 
/// async fn example() {
///     let conn = get_connection().await.unwrap();
///     // Use connection for database operations
/// }
/// ```
pub async fn get_connection() -> Result<Arc<DatabaseConnection>, DbError> {
    let conn = DB_CONN
    .get_or_init(|| async {
        info!("Initializing database connection...");
        dotenv().ok();
        match DbConfig::from_env() {
            Ok(config) => {
                info!("Successfully loaded database configuration: type={}, max_connections={}", config.db_type, config.max_connections);
                match config.db_type.as_str() {
                    "mysql" => match mysql::create_mysql_connection(&config).await {
                        Ok(conn) => {
                            info!("MySQL database connection pool created successfully");
                            Arc::new(conn)
                        },
                        Err(e) => {
                            error!("Failed to create MySQL connection pool: {}", e);
                            panic!("Failed to create MySQL connection: {}", e)
                        },
                    },
                    "postgres" => match postgresql::create_postgresql_connection(&config).await {
                        Ok(conn) => {
                            info!("PostgreSQL database connection pool created successfully");
                            Arc::new(conn)
                        },
                        Err(e) => {
                            error!("Failed to create PostgreSQL connection pool: {}", e);
                            panic!("Failed to create PostgreSQL connection: {}", e)
                        },
                    },
                    _ => {
                        error!("Unsupported database type: {}", config.db_type);
                        panic!("Invalid database type: {}", config.db_type)
                    },
                }
            },
            Err(e) => {
                error!("Failed to load database configuration: {}", e);
                panic!("Failed to load database config: {}", e)
            },
        }
    })
    .await;

    Ok(conn.clone())
}

pub async fn execute_sql_file(db: &DatabaseConnection, db_version: &str) -> Result<(), Box<dyn Error>> {
    let sql_file = match db.get_database_backend() {
        DatabaseBackend::Postgres => get_postgresql_sql_file(db_version),
        DatabaseBackend::MySql => get_mysql_sql_file(db_version),
        _ => return Err(Box::from("Unsupported database")),
    };
    // read SQL file
    let sql_content = std::fs::read_to_string(sql_file)?;
    // get sql type
    let db_backend = db.get_database_backend();
    // spilt sql by ;
    let statements = sql_content
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim());
    // begin transaction
    let txn = db.begin().await?;
    // execute sql
    for stmt in statements {
        let statement = Statement::from_string(db_backend, stmt.to_owned());
        if let Err(e) = txn.execute(statement).await {
            txn.rollback().await?; // failed rollback
            return Err(e.into());
        }
    }
    txn.commit().await?; // transaction commit
    Ok(())
}

fn get_postgresql_sql_file(db_version: &str) -> String {
    let mut path = PathBuf::new();
    path.push("rdb_sql");
    path.push("attestation_service");
    path.push("postgresql");
    path.push(format!("postgresql_{}.sql", db_version));
    path.to_str().unwrap().to_string()
}

fn get_mysql_sql_file(db_version: &str) -> String {
    let path = find_file(format!("mysql_{}.sql", db_version).as_str());
    path.map(|p| p.to_str().unwrap().to_string()).expect("Failed to get mysql_sql file")
}