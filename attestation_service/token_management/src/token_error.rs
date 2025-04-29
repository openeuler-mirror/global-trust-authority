use thiserror::Error;

// Generate token exception enumeration
#[derive(Debug, Error)]
pub enum GenerateTokenError {
    // Token generation failed
    #[error("Generate token failed: {0}")]
    GenerateTokenError(String),
}

/// Verify token exception enumeration
#[derive(Debug, Error)]
pub enum VerifyTokenError {
    // verify token failed
    #[error("Verify token failed: {0}")]
    VerifyTokenError(String),
}