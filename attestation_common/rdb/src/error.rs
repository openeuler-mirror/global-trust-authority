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