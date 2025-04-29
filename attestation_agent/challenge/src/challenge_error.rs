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
    /// User nonce not provided when required
    UserNonceNotProvided,
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
            Self::UserNonceNotProvided => write!(f, "User nonce must be provided when nonce_type is 'user'"),
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
