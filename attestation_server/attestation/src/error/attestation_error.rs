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
use plugin_manager::PluginError;

/// Custom error types for the attestation service
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Error indicating invalid input parameters
    #[error("{0}")]
    InvalidParameter(String),

    /// Error indicating failure in nonce verification process
    #[error("{0}")]
    NonceVerificationError(String),

    /// Error indicating failure in policy verification
    #[error("{0}")]
    PolicyVerificationError(String),

    /// Error indicating failure in evidence verification
    #[error("{0}")]
    EvidenceVerificationError(String),

    /// Error indicating failure in token generation
    #[error("Internal Server Error")]
    TokenGenerationError,

    /// Error indicating database operation failures
    #[error("Internal Server Error")]
    DatabaseError,

    /// Error indicating internal service errors
    #[error("Internal Server Error")]
    InternalError(String),

    /// Error indicating required plugin was not found
    #[error("{0}")]
    PluginNotFoundError(String),

    /// Error indicating policy was not found
    #[error("{0}")]
    PolicyNotFoundError(String),
}

/// Implementation of HTTP status code conversion and error message handling
impl AttestationError {
    /// Converts the error type to an appropriate HTTP status code
    ///
    /// # Returns
    /// * `StatusCode` - The corresponding HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidParameter(_) => StatusCode::BAD_REQUEST,
            Self::NonceVerificationError(_) => StatusCode::BAD_REQUEST,
            Self::PolicyVerificationError(_) => StatusCode::BAD_REQUEST,
            Self::EvidenceVerificationError(_) => StatusCode::BAD_REQUEST,
            Self::TokenGenerationError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PluginNotFoundError(_) => StatusCode::BAD_REQUEST,
            Self::PolicyNotFoundError(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// Gets the error message as a string
    ///
    /// # Returns
    /// * `String` - The error message
    pub fn message(&self) -> String {
        self.to_string()
    }
}

/// Common error type conversions for standard error types
impl From<std::io::Error> for AttestationError {
    fn from(error: std::io::Error) -> Self {
        Self::InternalError(error.to_string())
    }
}

impl From<serde_json::Error> for AttestationError {
    fn from(error: serde_json::Error) -> Self {
        Self::InternalError(format!("JSON processing error: {}", error))
    }
}

impl From<String> for AttestationError {
    fn from(err: String) -> Self {
        AttestationError::InternalError(err)
    }
}

impl From<&str> for AttestationError {
    fn from(err: &str) -> Self {
        AttestationError::InternalError(err.to_string())
    }
}

impl From<PluginError> for AttestationError {
    fn from(error: PluginError) -> Self {
        match error {
            PluginError::InputError(msg) => {
                AttestationError::EvidenceVerificationError(msg)
            }
            PluginError::InternalError(msg) => {
                AttestationError::InternalError(msg)
            }
        }
    }
}
