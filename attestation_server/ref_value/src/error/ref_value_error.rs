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

use actix_web::http::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RefValueError {
    // Cert Verify Occur Database Error
    #[error("Internal Server Error")]
    DbError(String),

    // Cert Verify Occur Verify Error
    #[error("{0}")]
    VerifyError(String),

    #[error("{0}")]
    JsonParseError(String),
    
    #[error("{0}")]
    InvalidParameter(String),

    #[error("Internal Server Error")]
    SignatureError(String),
}

impl RefValueError {
    /// Get corresponding HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            RefValueError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            RefValueError::VerifyError(_) => StatusCode::BAD_REQUEST,
            RefValueError::JsonParseError(_) => StatusCode::BAD_REQUEST,
            RefValueError::InvalidParameter(_) => StatusCode::BAD_REQUEST,
            RefValueError::SignatureError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get error message
    pub fn message(&self) -> String {
        self.to_string()
    }
}

/// Convert from other error types to PolicyError
impl From<String> for RefValueError {
    fn from(err: String) -> Self {
        RefValueError::DbError(err)
    }
}

impl From<&str> for RefValueError {
    fn from(err: &str) -> Self {
        RefValueError::DbError(err.to_string())
    }
}

impl From<std::io::Error> for RefValueError {
    fn from(err: std::io::Error) -> Self {
        RefValueError::DbError(err.to_string())
    }
}

impl From<serde_json::Error> for RefValueError {
    fn from(err: serde_json::Error) -> Self {
        RefValueError::DbError(err.to_string())
    }
}