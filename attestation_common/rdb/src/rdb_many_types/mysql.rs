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

//! MySQL database connection module
//! Handle MySQL-specific connection pool creation and management

use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::time::Duration;
use log::info;
use crate::config::DbConfig;
use crate::DbError;

/// Create MySQL database connection
pub(crate) async fn create_mysql_connection(config: &DbConfig) -> Result<DatabaseConnection, DbError> {
    let mut opt = ConnectOptions::new(config.url.clone());
    opt.max_connections(config.max_connections)
       .connect_timeout(Duration::from_secs(config.timeout)).sqlx_logging(false);
    info!("MySQL connection parameters configured, establishing connection...");

    Database::connect(opt)
        .await
        .map_err(|e| DbError::ConnectionError(e.to_string()))
}