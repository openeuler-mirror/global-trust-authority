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
use actix_web::http::StatusCode;

/// Policy operation errors
#[derive(Error, Debug, Clone)]
pub enum PolicyError {
    /// Incorrect input parameter format
    #[error("Incorrect formatting of input parameters: {0}")]
    IncorrectFormatError(String),

    /// Missing required parameters
    #[error("Required parameters are missing: {0}")]
    MissingRequiredParamError(String),

    /// Policy file not found
    #[error("Policy not found: {0}")]
    PolicyNotFoundError(String),

    /// Policy is existing
    #[error("Policy is existing: {0}")]
    PolicyExistError(String),

    /// Policy file signature verification failed
    #[error("Failure to verify signature of policy file: {0}")]
    PolicySignatureVerificationError(String),

    /// Syntax error occurred when matching sample output with policy
    #[error("Syntax error when sample output matches policy: {0}")]
    PolicyMatchSyntaxError(String),

    /// Failed to verify signature of policy retrieved from database
    #[error("Failed to validate the policy signature taken out of the database: {0}")]
    DatabasePolicySignatureError(String),

    /// Database operation failed
    #[error("Database operation failed: {0}")]
    DatabaseOperationError(String),

    /// Database connection failed
    #[error("Database connection failed: {0}")]
    DatabaseConnectionError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Invalid policy content
    #[error("Invalid policy content: {0}")]
    InvalidPolicyContent(String),

    // Policy signature failure
    #[error("Policy signature failure: {0}")]
    PolicySignatureFailure(String),

    // Single user policy file creation limit reached
    #[error("Strategy has reached its limit and cannot be created: {0}")]
    PolicyLimitReached(String),

    // Policy content size limit reached
    #[error("Strategy content is greater than the cap: {0}")]
    PolicyContentSizeLimitReached(String),

    // Policy version overflow error
    #[error("Policy version has reached maximum value: {0}")]
    PolicyVersionOverflowError(String),

    // Too many requests error
    #[error("Too many requests: {0}")]
    TooManyRequestsError(String),
}

impl PolicyError {
    /// Get corresponding HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            PolicyError::IncorrectFormatError(_) => StatusCode::BAD_REQUEST,
            PolicyError::PolicyNotFoundError(_) => StatusCode::BAD_REQUEST,
            PolicyError::PolicyExistError(_) => StatusCode::BAD_REQUEST,
            PolicyError::MissingRequiredParamError(_) => StatusCode::BAD_REQUEST,
            PolicyError::PolicySignatureVerificationError(_) => StatusCode::BAD_REQUEST,
            PolicyError::PolicyMatchSyntaxError(_) => StatusCode::BAD_REQUEST,
            PolicyError::DatabasePolicySignatureError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            PolicyError::DatabaseOperationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            PolicyError::DatabaseConnectionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            PolicyError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            PolicyError::InvalidPolicyContent(_) => StatusCode::BAD_REQUEST,
            PolicyError::PolicySignatureFailure(_) => StatusCode::INTERNAL_SERVER_ERROR,
            PolicyError::PolicyLimitReached(_) => StatusCode::BAD_REQUEST,
            PolicyError::PolicyContentSizeLimitReached(_) => StatusCode::BAD_REQUEST,
            PolicyError::PolicyVersionOverflowError(_) => StatusCode::BAD_REQUEST,
            PolicyError::TooManyRequestsError(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// Get error message
    pub fn message(&self) -> String {
        self.to_string()
    }
}

/// Convert from other error types to PolicyError
impl From<String> for PolicyError {
    fn from(err: String) -> Self {
        PolicyError::InternalError(err)
    }
}

impl From<&str> for PolicyError {
    fn from(err: &str) -> Self {
        PolicyError::InternalError(err.to_string())
    }
}

impl From<std::io::Error> for PolicyError {
    fn from(err: std::io::Error) -> Self {
        PolicyError::InternalError(err.to_string())
    }
}

impl From<serde_json::Error> for PolicyError {
    fn from(err: serde_json::Error) -> Self {
        PolicyError::InvalidPolicyContent(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn test_error_status_codes() {
        let cases = [
            (PolicyError::IncorrectFormatError("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::PolicyNotFoundError("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::PolicyExistError("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::MissingRequiredParamError("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::PolicySignatureVerificationError("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::PolicyMatchSyntaxError("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::DatabasePolicySignatureError("test".into()), StatusCode::INTERNAL_SERVER_ERROR),
            (PolicyError::DatabaseOperationError("test".into()), StatusCode::INTERNAL_SERVER_ERROR),
            (PolicyError::DatabaseConnectionError("test".into()), StatusCode::INTERNAL_SERVER_ERROR),
            (PolicyError::InternalError("test".into()), StatusCode::INTERNAL_SERVER_ERROR),
            (PolicyError::InvalidPolicyContent("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::PolicySignatureFailure("test".into()), StatusCode::INTERNAL_SERVER_ERROR),
            (PolicyError::PolicyLimitReached("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::PolicyContentSizeLimitReached("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::PolicyVersionOverflowError("test".into()), StatusCode::BAD_REQUEST),
            (PolicyError::TooManyRequestsError("test".into()), StatusCode::TOO_MANY_REQUESTS),
        ];

        for (error, expected_status) in cases {
            assert_eq!(error.status_code(), expected_status);
        }
    }

    #[test]
    fn test_error_messages() {
        let error = PolicyError::IncorrectFormatError("invalid format".into());
        assert_eq!(error.message(), "Incorrect formatting of input parameters: invalid format");

        let error = PolicyError::PolicyNotFoundError("policy123".into());
        assert_eq!(error.message(), "Policy not found: policy123");
    }

    #[test]
    fn test_from_string() {
        let error: PolicyError = "test error".to_string().into();
        assert!(matches!(error, PolicyError::InternalError(_)));
        assert_eq!(error.message(), "Internal error: test error");
    }

    #[test]
    fn test_from_str() {
        let error: PolicyError = "test error".into();
        assert!(matches!(error, PolicyError::InternalError(_)));
        assert_eq!(error.message(), "Internal error: test error");
    }

    #[test]
    fn test_from_io_error() {
        let io_error = IoError::new(ErrorKind::NotFound, "file not found");
        let error: PolicyError = io_error.into();
        assert!(matches!(error, PolicyError::InternalError(_)));
        assert_eq!(error.message(), "Internal error: file not found");
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let error: PolicyError = json_error.into();
        assert!(matches!(error, PolicyError::InvalidPolicyContent(_)));
    }
}