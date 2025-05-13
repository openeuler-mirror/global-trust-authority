use actix_web::http::StatusCode;
use thiserror::Error;

/// Custom error types for the attestation service
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Error indicating invalid input parameters
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Error indicating failure in nonce verification process
    #[error("Nonce verification failed: {0}")]
    NonceVerificationError(String),

    /// Error indicating failure in policy verification
    #[error("Policy verification failed: {0}")]
    PolicyVerificationError(String),

    /// Error indicating failure in policy export operation
    #[error("Get export policy failed: {0}")]
    GetExportPolicyError(String),

    /// Error indicating failure in evidence verification
    #[error("Evidence verification failed: {0}")]
    EvidenceVerificationError(String),

    /// Error indicating failure in token generation
    #[error("Token generation failed: {0}")]
    TokenGenerationError(String),

    /// Error indicating database operation failures
    #[error("Database operation failed: {0}")]
    DatabaseError(String),

    /// Error indicating internal service errors
    #[error("Internal service error: {0}")]
    InternalError(String),

    /// Error indicating required plugin was not found
    #[error("Plugin not found: {0}")]
    PluginNotFoundError(String),

    /// Error indicating policy was not found
    #[error("Policy not found: {0}")]
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
            Self::GetExportPolicyError(_) => StatusCode::BAD_REQUEST,
            Self::EvidenceVerificationError(_) => StatusCode::BAD_REQUEST,
            Self::TokenGenerationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
