use awc::error::JsonPayloadError;
use openssl::error::ErrorStack;
use std::fmt;

#[derive(Debug)]
pub struct KeyManagerError {
    message: String,
}

impl KeyManagerError {
    pub fn new<T: Into<String>>(message: T) -> Self {
        KeyManagerError {
            message: message.into(),
        }
    }
}

impl fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for KeyManagerError {}

impl From<serde_yaml::Error> for KeyManagerError {
    fn from(e: serde_yaml::Error) -> Self {
        KeyManagerError::new(e.to_string())
    }
}

impl From<anyhow::Error> for KeyManagerError {
    fn from(err: anyhow::Error) -> Self {
        KeyManagerError::new(err.to_string())
    }
}

impl From<ErrorStack> for KeyManagerError {
    fn from(err: ErrorStack) -> Self {
        KeyManagerError::new(err.to_string())
    }
}

impl From<JsonPayloadError> for KeyManagerError {
    fn from(err: JsonPayloadError) -> Self {
        KeyManagerError::new(err.to_string())
    }
}

impl From<sea_orm::DbErr> for KeyManagerError {
    fn from(err: sea_orm::DbErr) -> Self {
        KeyManagerError::new(err.to_string())
    }
}

#[cfg(test)]
#[allow(warnings)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use awc::error::JsonPayloadError;
    use openssl::error::ErrorStack;
    use sea_orm::DbErr;

    #[test]
    fn test_new_error() {
        let message = "Test error message";
        let error = KeyManagerError::new(message);
        assert_eq!(error.message, message);
        assert_eq!(format!("{}", error), message);
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow!("Anyhow error occurred");
        let key_error: KeyManagerError = anyhow_err.into();
        assert_eq!(key_error.message, "Anyhow error occurred");
    }

    #[test]
    fn test_from_error_stack() {
        // Create an openssl error (example)
        let stack_err = ErrorStack::get();
        let key_error: KeyManagerError = stack_err.into();
        assert!(!key_error.message.is_empty());
    }

    #[test]
    fn test_from_json_payload_error() {
        // Create mock JsonPayloadError
        let payload_err = JsonPayloadError::ContentType;
        let key_error: KeyManagerError = payload_err.into();
        assert_eq!(key_error.message, "Content type error");
    }

    #[test]
    fn test_from_sea_orm_error() {
        let db_err = DbErr::Conn(sea_orm::RuntimeErr::Internal(
            "Database connection failed".to_string(),
        ));
        let key_error: KeyManagerError = db_err.into();
        assert_eq!(
            key_error.message,
            "Connection Error: Database connection failed"
        );
    }

    #[test]
    fn test_error_trait() {
        let error = KeyManagerError::new("Test error");
        let dyn_error: &dyn std::error::Error = &error;
        assert_eq!(dyn_error.to_string(), "Test error");
    }

    #[test]
    fn test_debug_implementation() {
        let error = KeyManagerError::new("Debug test");
        let debug_output = format!("{:?}", error);
        assert!(debug_output.contains("KeyManagerError"));
        assert!(debug_output.contains("Debug test"));
    }
}
