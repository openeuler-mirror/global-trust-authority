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

use thiserror::Error;
use rdb::DbError;

#[derive(Error, Debug, Clone)]
pub enum RegisterError {

    #[error("Internal service error: {0}")]
    InternalError(String),

    #[error("Pbkdf2 generate key error: {0}")]
    GenerateApiKeyError(String),

    #[error("Register access database error: {0}")]
    DbError(String),

    #[error("Record not found: {0}")]
    RecordNotFound(String),

    #[error("Decode base64 error: {0}")]
    Base64DecodeFound(String)

}

impl RegisterError {

    /// Gets the error message as a string
    ///
    /// # Returns
    /// * `String` - The error messag   
    pub fn message(&self) -> String {
        self.to_string()
    }
}

/// Common error type conversions for standard error types
impl From<std::io::Error> for RegisterError {
    fn from(error: std::io::Error) -> Self {
        Self::InternalError(error.to_string())
    }
}

impl From<serde_json::Error> for RegisterError {
    fn from(error: serde_json::Error) -> Self {
        Self::InternalError(format!("JSON processing error: {}", error))
    }
}

impl From<String> for RegisterError {
    fn from(err: String) -> Self {
        RegisterError::InternalError(err)
    }
}

impl From<&str> for RegisterError {
    fn from(err: &str) -> Self {
        RegisterError::InternalError(err.to_string())
    }
}

impl From<DbError> for RegisterError {
    fn from(err: DbError) -> Self {
        RegisterError::DbError(err.to_string())
    }
}

impl From<sea_orm::DbErr> for RegisterError {
    fn from(err: sea_orm::DbErr) -> Self {
        RegisterError::DbError(err.to_string())
    }
}