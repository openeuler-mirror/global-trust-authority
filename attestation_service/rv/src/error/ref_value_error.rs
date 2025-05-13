use actix_web::http::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RefValueError {
    // Cert Verify Occur Database Error
    #[error("RefValue occur database  error: {0}")]
    DbError(String),

    // Cert Verify Occur Verify Error
    #[error("RefValue occur verify error: {0}")]
    VerifyError(String),

    #[error("json parse error: {0}")]
    JsonParseError(String),
    
    #[error("invalid param: {0}")]
    InvalidParameter(String),

    #[error("signature error: {0}")]
    SignatureError(String),
}

impl RefValueError {
    /// Get corresponding HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            RefValueError::DbError(_) => StatusCode::BAD_REQUEST,
            RefValueError::VerifyError(_) => StatusCode::BAD_REQUEST,
            RefValueError::JsonParseError(_) => StatusCode::BAD_REQUEST,
            RefValueError::InvalidParameter(_) => StatusCode::BAD_REQUEST,
            RefValueError::SignatureError(_) => StatusCode::BAD_REQUEST,
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