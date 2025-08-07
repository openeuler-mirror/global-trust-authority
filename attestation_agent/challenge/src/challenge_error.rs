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

use std::error::Error;
use std::fmt;

/// Error types that may occur during the remote attestation challenge process
/// Defines all possible errors that can happen in the challenge process, including config, plugin, network, nonce, and token errors.
#[derive(Debug)]
pub enum ChallengeError {
    /// Configuration file related errors, including specific error messages
    ConfigError(String),
    /// Specified plugin not found in the system, includes plugin name
    PluginNotFound(String),
    /// No enabled plugins found in the system
    NoEnabledPlugins,

    /// Errors during evidence collection, includes failure reason
    EvidenceCollectionFailed(String),
    /// No valid evidence collected, includes specific reason
    NoValidEvidence(String),

    /// Nonce type error, includes invalid nonce type information
    NonceTypeError(String),
    /// Nonce value is empty
    NonceValueEmpty,
    /// Nonce not provided when required
    NonceNotProvided,
    /// Nonce is invalid
    NonceInvalid(String),

    /// Token not received in server response
    TokenNotReceived,

    /// Request parsing error, includes parsing failure reason
    RequestParseError(String),
    /// Network communication error, includes specific error message
    NetworkError(String),
    /// Server-side error, includes server returned error message
    ServerError(String),

    /// Internal system error, includes specific error message
    InternalError(String),

    /// Token related errors
    TokenError(TokenError),
}

/// Error types specific to token operations
/// Used for errors that occur during token request and retrieval.
#[derive(Debug)]
pub enum TokenError {
    /// Challenge request error
    ChallengeError(String),
    /// Token not found error
    TokenNotFound(String),
}

// Display implementation for TokenError for readable error messages
impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::ChallengeError(msg) => write!(f, "Challenge error: {}", msg),
            TokenError::TokenNotFound(msg) => write!(f, "Token not found: {}", msg),
        }
    }
}

impl TokenError {
    pub fn challenge_error<S: Into<String>>(msg: S) -> Self {
        TokenError::ChallengeError(msg.into())
    }

    pub fn token_not_found<S: Into<String>>(msg: S) -> Self {
        TokenError::TokenNotFound(msg.into())
    }
}

// Display implementation for ChallengeError for readable error messages
impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Configuration related errors
            Self::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            Self::PluginNotFound(name) => write!(f, "Plugin not found: {}", name),
            Self::NoEnabledPlugins => write!(f, "No enabled plugins found in configuration"),

            // Evidence collection errors
            Self::EvidenceCollectionFailed(msg) => write!(f, "Failed to collect evidence: {}", msg),
            Self::NoValidEvidence(msg) => write!(f, "No valid evidence collected: {}", msg),

            // Nonce related errors
            Self::NonceTypeError(msg) => write!(f, "Invalid nonce type: {}", msg),
            Self::NonceValueEmpty => write!(f, "Nonce value cannot be empty"),
            Self::NonceNotProvided => write!(f, "Nonce must be provided when nonce_type is 'default' or null"),
            Self::NonceInvalid(msg) => write!(f, "Invalid nonce: {}", msg),

            // Challenge process errors
            Self::TokenNotReceived => write!(f, "No token received in server response"),

            // Request and response errors
            Self::RequestParseError(msg) => write!(f, "Failed to parse request: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::ServerError(msg) => write!(f, "Server error: {}", msg),

            // Other errors
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),

            // Token errors
            Self::TokenError(e) => write!(f, "{}", e),
        }
    }
}

// Implement std::error::Error for ChallengeError and TokenError
impl Error for ChallengeError {}
impl Error for TokenError {}

// Implement conversions from other error types to ChallengeError
// Allows using ? operator with different error types in challenge logic.
impl From<std::io::Error> for ChallengeError {
    fn from(err: std::io::Error) -> Self {
        ChallengeError::InternalError(err.to_string())
    }
}

impl From<serde_json::Error> for ChallengeError {
    fn from(err: serde_json::Error) -> Self {
        ChallengeError::RequestParseError(err.to_string())
    }
}

impl From<String> for ChallengeError {
    fn from(err: String) -> Self {
        ChallengeError::InternalError(err)
    }
}

impl From<&str> for ChallengeError {
    fn from(err: &str) -> Self {
        ChallengeError::InternalError(err.to_string())
    }
}

impl From<plugin_manager::PluginError> for ChallengeError {
    fn from(err: plugin_manager::PluginError) -> Self {
        ChallengeError::EvidenceCollectionFailed(err.to_string())
    }
}

// Conversion from TokenError to ChallengeError for unified error handling
impl From<TokenError> for ChallengeError {
    fn from(err: TokenError) -> Self {
        ChallengeError::TokenError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_error_display() {
        let config_error = ChallengeError::ConfigError("test config error".to_string());
        assert_eq!(config_error.to_string(), "Configuration error: test config error");

        let plugin_error = ChallengeError::PluginNotFound("test_plugin".to_string());
        assert_eq!(plugin_error.to_string(), "Plugin not found: test_plugin");

        let no_plugins = ChallengeError::NoEnabledPlugins;
        assert_eq!(no_plugins.to_string(), "No enabled plugins found in configuration");

        let evidence_error = ChallengeError::EvidenceCollectionFailed("evidence failed".to_string());
        assert_eq!(evidence_error.to_string(), "Failed to collect evidence: evidence failed");

        let nonce_error = ChallengeError::NonceInvalid("invalid nonce".to_string());
        assert_eq!(nonce_error.to_string(), "Invalid nonce: invalid nonce");

        let network_error = ChallengeError::NetworkError("network failed".to_string());
        assert_eq!(network_error.to_string(), "Network error: network failed");
    }

    #[test]
    fn test_token_error_display() {
        let challenge_error = TokenError::ChallengeError("challenge failed".to_string());
        assert_eq!(challenge_error.to_string(), "Challenge error: challenge failed");

        let token_not_found = TokenError::TokenNotFound("token missing".to_string());
        assert_eq!(token_not_found.to_string(), "Token not found: token missing");
    }

    #[test]
    fn test_token_error_constructors() {
        let challenge_error = TokenError::challenge_error("test challenge error");
        assert!(matches!(challenge_error, TokenError::ChallengeError(_)));

        let token_not_found = TokenError::token_not_found("test token not found");
        assert!(matches!(token_not_found, TokenError::TokenNotFound(_)));
    }

    #[test]
    fn test_error_conversions() {
        // Test From<String>
        let string_error: ChallengeError = "test string error".into();
        assert!(matches!(string_error, ChallengeError::InternalError(_)));

        // Test From<&str>
        let str_error: ChallengeError = "test str error".into();
        assert!(matches!(str_error, ChallengeError::InternalError(_)));

        // Test From<TokenError>
        let token_error = TokenError::ChallengeError("test".to_string());
        let challenge_error: ChallengeError = token_error.into();
        assert!(matches!(challenge_error, ChallengeError::TokenError(_)));
    }

    #[test]
    fn test_serde_json_error_conversion() {
        let json_str = "invalid json";
        let json_error = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let challenge_error: ChallengeError = json_error.into();
        assert!(matches!(challenge_error, ChallengeError::RequestParseError(_)));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let challenge_error: ChallengeError = io_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));
    }

    #[test]
    fn test_challenge_error_display_comprehensive() {
        // Test all error types for display
        let config_error = ChallengeError::ConfigError("config failed".to_string());
        assert_eq!(config_error.to_string(), "Configuration error: config failed");

        let plugin_error = ChallengeError::PluginNotFound("plugin_name".to_string());
        assert_eq!(plugin_error.to_string(), "Plugin not found: plugin_name");

        let no_plugins = ChallengeError::NoEnabledPlugins;
        assert_eq!(no_plugins.to_string(), "No enabled plugins found in configuration");

        let evidence_error = ChallengeError::EvidenceCollectionFailed("evidence failed".to_string());
        assert_eq!(evidence_error.to_string(), "Failed to collect evidence: evidence failed");

        let no_valid_evidence = ChallengeError::NoValidEvidence("no evidence".to_string());
        assert_eq!(no_valid_evidence.to_string(), "No valid evidence collected: no evidence");

        let nonce_type_error = ChallengeError::NonceTypeError("invalid type".to_string());
        assert_eq!(nonce_type_error.to_string(), "Invalid nonce type: invalid type");

        let nonce_value_empty = ChallengeError::NonceValueEmpty;
        assert_eq!(nonce_value_empty.to_string(), "Nonce value cannot be empty");

        let nonce_not_provided = ChallengeError::NonceNotProvided;
        assert_eq!(nonce_not_provided.to_string(), "Nonce must be provided when nonce_type is 'default' or null");

        let nonce_invalid = ChallengeError::NonceInvalid("invalid nonce".to_string());
        assert_eq!(nonce_invalid.to_string(), "Invalid nonce: invalid nonce");

        let token_not_received = ChallengeError::TokenNotReceived;
        assert_eq!(token_not_received.to_string(), "No token received in server response");

        let request_parse_error = ChallengeError::RequestParseError("parse failed".to_string());
        assert_eq!(request_parse_error.to_string(), "Failed to parse request: parse failed");

        let network_error = ChallengeError::NetworkError("network failed".to_string());
        assert_eq!(network_error.to_string(), "Network error: network failed");

        let server_error = ChallengeError::ServerError("server failed".to_string());
        assert_eq!(server_error.to_string(), "Server error: server failed");

        let internal_error = ChallengeError::InternalError("internal failed".to_string());
        assert_eq!(internal_error.to_string(), "Internal error: internal failed");

        let token_error = TokenError::ChallengeError("token challenge failed".to_string());
        let challenge_error = ChallengeError::TokenError(token_error);
        assert_eq!(challenge_error.to_string(), "Challenge error: token challenge failed");
    }

    #[test]
    fn test_token_error_display_comprehensive() {
        let challenge_error = TokenError::ChallengeError("challenge failed".to_string());
        assert_eq!(challenge_error.to_string(), "Challenge error: challenge failed");

        let token_not_found = TokenError::TokenNotFound("token missing".to_string());
        assert_eq!(token_not_found.to_string(), "Token not found: token missing");

        // Test with empty strings
        let challenge_error = TokenError::ChallengeError("".to_string());
        assert_eq!(challenge_error.to_string(), "Challenge error: ");

        let token_not_found = TokenError::TokenNotFound("".to_string());
        assert_eq!(token_not_found.to_string(), "Token not found: ");
    }

    #[test]
    fn test_token_error_constructors_comprehensive() {
        let challenge_error = TokenError::challenge_error("test challenge error");
        assert!(matches!(challenge_error, TokenError::ChallengeError(_)));
        assert_eq!(challenge_error.to_string(), "Challenge error: test challenge error");

        let token_not_found = TokenError::token_not_found("test token not found");
        assert!(matches!(token_not_found, TokenError::TokenNotFound(_)));
        assert_eq!(token_not_found.to_string(), "Token not found: test token not found");

        // Test with different string types
        let challenge_error = TokenError::challenge_error(String::from("owned string"));
        assert!(matches!(challenge_error, TokenError::ChallengeError(_)));

        let token_not_found = TokenError::token_not_found(String::from("owned string"));
        assert!(matches!(token_not_found, TokenError::TokenNotFound(_)));
    }

    #[test]
    fn test_error_conversions_comprehensive() {
        // Test From<String>
        let string_error: ChallengeError = "test string error".into();
        assert!(matches!(string_error, ChallengeError::InternalError(_)));
        assert_eq!(string_error.to_string(), "Internal error: test string error");

        // Test From<&str>
        let str_error: ChallengeError = "test str error".into();
        assert!(matches!(str_error, ChallengeError::InternalError(_)));
        assert_eq!(str_error.to_string(), "Internal error: test str error");

        // Test From<TokenError>
        let token_error = TokenError::ChallengeError("test".to_string());
        let challenge_error: ChallengeError = token_error.into();
        assert!(matches!(challenge_error, ChallengeError::TokenError(_)));
        assert_eq!(challenge_error.to_string(), "Challenge error: test");

        // Test From<TokenError> with TokenNotFound
        let token_error = TokenError::TokenNotFound("not found".to_string());
        let challenge_error: ChallengeError = token_error.into();
        assert!(matches!(challenge_error, ChallengeError::TokenError(_)));
        assert_eq!(challenge_error.to_string(), "Token not found: not found");
    }

    #[test]
    fn test_serde_json_error_conversion_comprehensive() {
        // Test with invalid JSON
        let json_str = "invalid json";
        let json_error = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let challenge_error: ChallengeError = json_error.into();
        assert!(matches!(challenge_error, ChallengeError::RequestParseError(_)));

        // Test with incomplete JSON
        let json_str = r#"{"key": "value""#;
        let json_error = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let challenge_error: ChallengeError = json_error.into();
        assert!(matches!(challenge_error, ChallengeError::RequestParseError(_)));

        // Test with wrong type
        let json_str = r#"{"key": "value"}"#;
        let json_error = serde_json::from_str::<i32>(json_str).unwrap_err();
        let challenge_error: ChallengeError = json_error.into();
        assert!(matches!(challenge_error, ChallengeError::RequestParseError(_)));
    }

    #[test]
    fn test_io_error_conversion_comprehensive() {
        // Test different IO error kinds
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let challenge_error: ChallengeError = io_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));

        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let challenge_error: ChallengeError = io_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));

        let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        let challenge_error: ChallengeError = io_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));

        let io_error = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let challenge_error: ChallengeError = io_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));
    }

    #[test]
    fn test_error_trait_implementation() {
        // Test that ChallengeError implements std::error::Error
        let error = ChallengeError::ConfigError("test".to_string());
        let error_ref: &dyn std::error::Error = &error;
        assert_eq!(error_ref.to_string(), "Configuration error: test");

        // Test that TokenError implements std::error::Error
        let token_error = TokenError::ChallengeError("test".to_string());
        let error_ref: &dyn std::error::Error = &token_error;
        assert_eq!(error_ref.to_string(), "Challenge error: test");
    }

    #[test]
    fn test_error_debug_implementation() {
        // Test Debug implementation for ChallengeError
        let error = ChallengeError::ConfigError("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("ConfigError"));
        assert!(debug_str.contains("test"));

        // Test Debug implementation for TokenError
        let token_error = TokenError::ChallengeError("test".to_string());
        let debug_str = format!("{:?}", token_error);
        assert!(debug_str.contains("ChallengeError"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_error_pattern_matching() {
        // Test pattern matching for all ChallengeError variants
        let errors = vec![
            ChallengeError::ConfigError("config".to_string()),
            ChallengeError::PluginNotFound("plugin".to_string()),
            ChallengeError::NoEnabledPlugins,
            ChallengeError::EvidenceCollectionFailed("evidence".to_string()),
            ChallengeError::NoValidEvidence("no evidence".to_string()),
            ChallengeError::NonceTypeError("type".to_string()),
            ChallengeError::NonceValueEmpty,
            ChallengeError::NonceNotProvided,
            ChallengeError::NonceInvalid("invalid".to_string()),
            ChallengeError::TokenNotReceived,
            ChallengeError::RequestParseError("parse".to_string()),
            ChallengeError::NetworkError("network".to_string()),
            ChallengeError::ServerError("server".to_string()),
            ChallengeError::InternalError("internal".to_string()),
            ChallengeError::TokenError(TokenError::ChallengeError("token".to_string())),
        ];

        for error in errors {
            match error {
                ChallengeError::ConfigError(_) => {},
                ChallengeError::PluginNotFound(_) => {},
                ChallengeError::NoEnabledPlugins => {},
                ChallengeError::EvidenceCollectionFailed(_) => {},
                ChallengeError::NoValidEvidence(_) => {},
                ChallengeError::NonceTypeError(_) => {},
                ChallengeError::NonceValueEmpty => {},
                ChallengeError::NonceNotProvided => {},
                ChallengeError::NonceInvalid(_) => {},
                ChallengeError::TokenNotReceived => {},
                ChallengeError::RequestParseError(_) => {},
                ChallengeError::NetworkError(_) => {},
                ChallengeError::ServerError(_) => {},
                ChallengeError::InternalError(_) => {},
                ChallengeError::TokenError(_) => {},
            }
        }

        // Test pattern matching for TokenError variants
        let token_errors = vec![
            TokenError::ChallengeError("challenge".to_string()),
            TokenError::TokenNotFound("not found".to_string()),
        ];

        for error in token_errors {
            match error {
                TokenError::ChallengeError(_) => {},
                TokenError::TokenNotFound(_) => {},
            }
        }
    }
}
