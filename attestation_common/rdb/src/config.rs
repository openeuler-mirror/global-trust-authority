/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Database Configuration Module
//! Handles environment variables and connection settings

use std::env;
use log::{info, error};
#[allow(unused_imports)]
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
    /// Loads database configuration from environment variables.
    ///
    /// In debug mode, it attempts to load variables from a `.env.dev` file
    /// located by `env_config_parse::find_file`.
    ///
    /// It requires the `DB_TYPE` environment variable to be set to either "mysql" or "postgres".
    /// Based on `DB_TYPE`, it requires either `MYSQL_DATABASE_URL` or `POSTGRESQL_DATABASE_URL`.
    ///
    /// Optional environment variables `DATABASE_MAX_CONNECTIONS` and `DATABASE_TIMEOUT`
    /// are used for connection pool settings, defaulting to 20 and 30 seconds respectively
    /// if not set or invalid.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` containing the loaded `DbConfig` on success.
    /// Returns `Err(DbError)` if required environment variables are missing,
    /// cannot be parsed, or if `DB_TYPE` is unsupported.
    /// 
    /// # Errors
    /// 
    /// * `DbError::InvalidDatabaseType` - If `DB_TYPE` is unsupported.
    pub fn from_env() -> Result<Self, DbError> {
        info!("get db config from env");
        #[cfg(debug_assertions)]
        {
            dotenv::dotenv().ok().map(|_| std::env::vars().for_each(|(k, _)| std::env::remove_var(&k)));
            let file_path = env_config_parse::find_file(".env.dev").map(|p| p.to_str().unwrap().to_string()).unwrap();
            dotenv::from_filename(file_path).expect("Failed to load .env.dev");
        }
        let mut db_type = env::var("DB_TYPE").expect("DB_TYPE must be set");
        db_type = db_type.to_lowercase();
        let url = match db_type.as_str() {
            "mysql" => {
                info!("db type is mysql");
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