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

use actix_web::{http::StatusCode, HttpResponse};
use log::error;
use serde_json::json;
use challenge::challenge_error::{ChallengeError, TokenError};

/// Creates a standardized error response for HTTP endpoints
///
/// # Arguments
/// * `error` - Any error type that implements Display trait
/// * `status` - HTTP status code for the response
///
/// # Returns
/// * `HttpResponse` - JSON formatted error response with message
///
/// # Behavior
/// - For `BAD_REQUEST` (400), logs as request validation failure
/// - For other status codes, logs as operation failure
/// - Returns JSON response with error message and appropriate status code
pub fn create_error_response(error: impl std::fmt::Display, status: StatusCode) -> HttpResponse {
    let message = error.to_string();
    if status == StatusCode::BAD_REQUEST {
        error!("Request validation failed: {}", message);
    } else {
        error!("Operation failed: {}", message);
    }
    HttpResponse::build(status).json(json!({ "message": message }))
}

/// Creates a standardized error response for ChallengeError
/// Maps different ChallengeError variants to appropriate HTTP status codes
///
/// # Arguments
/// * `error` - ChallengeError instance to be converted to an HTTP response
///
/// # Returns
/// * `HttpResponse` - JSON formatted error response with appropriate status code and message
///
/// # Status Code Mapping
///
/// ## 400 Bad Request - Client-side errors
/// - `RequestParseError`: Request parsing failed
/// - `NonceTypeError`: Invalid nonce type
/// - `NonceValueEmpty`: Nonce value is empty
/// - `NonceNotProvided`: Nonce not provided when required
/// - `NonceInvalid`: Invalid nonce value
/// - `PluginNotFound`: Requested plugin not found
/// - `TokenError::InvalidTokenFormat`: Invalid token format
///
/// ## 500 Internal Server Error - Server-side errors
/// - `ConfigError`: Configuration error
/// - `InternalError`: General internal server error
/// - `EvidenceCollectionFailed`: Failed to collect evidence
/// - `NoValidEvidence`: No valid evidence was collected
/// - `TokenError::ChallengeError`: Challenge error
/// - `TokenError::TokenNotFound`: Token not found
///
/// ## 503 Service Unavailable - Service errors
/// - `NetworkError`: Network-related errors
/// - `ServerError`: Server-related errors
/// - `TokenNotReceived`: No token received in server response
pub fn create_challenge_error_response(error: ChallengeError) -> HttpResponse {
    let (status, message) = match error {
        // 400 Bad Request
        ChallengeError::PluginNotFound(name) => {
            (StatusCode::BAD_REQUEST, format!("Plugin not found: {}", name))
        },
        ChallengeError::NonceTypeError(msg) => {
            (StatusCode::BAD_REQUEST, format!("Invalid nonce type: {}", msg))
        },
        ChallengeError::NonceValueEmpty => {
            (StatusCode::BAD_REQUEST, "Nonce value cannot be empty".to_string())
        },
        ChallengeError::NonceNotProvided => {
            (StatusCode::BAD_REQUEST, "Nonce must be provided when nonce_type is 'default' or null".to_string())
        },
        ChallengeError::NonceInvalid(msg) => {
            (StatusCode::BAD_REQUEST, format!("Invalid nonce: {}", msg))
        },
         ChallengeError::RequestParseError(msg) => {
            (StatusCode::BAD_REQUEST, format!("Request parsing failed: {}", msg))
        },
        ChallengeError::TokenError(TokenError::InvalidTokenFormat(msg)) => {
            (StatusCode::BAD_REQUEST, format!("Invalid token format: {}", msg))
        },

        // 500 Internal Server Error
        ChallengeError::ConfigError(msg) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Configuration error: {}", msg))
        },
        ChallengeError::EvidenceCollectionFailed(msg) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Evidence collection failed: {}", msg))
        },
        ChallengeError::NoValidEvidence(msg) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("No valid evidence collected: {}", msg))
        },
        ChallengeError::InternalError(msg) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Internal server error: {}", msg))
        },
        ChallengeError::TokenError(TokenError::ChallengeError(msg)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Challenge error: {}", msg))
        },
        ChallengeError::TokenError(TokenError::TokenNotFound(msg)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Token not found: {}", msg))
        },

        // 503 Service Unavailable
        ChallengeError::TokenNotReceived => {
            (StatusCode::SERVICE_UNAVAILABLE, "No token received in server response".to_string())
        },
        ChallengeError::NetworkError(msg) => {
            (StatusCode::SERVICE_UNAVAILABLE, format!("Network error: {}", msg))
        },
        ChallengeError::ServerError(msg) => {
            (StatusCode::SERVICE_UNAVAILABLE, format!("Server error: {}", msg))
        },
    };

    HttpResponse::build(status).json(json!({ "message": message }))
}