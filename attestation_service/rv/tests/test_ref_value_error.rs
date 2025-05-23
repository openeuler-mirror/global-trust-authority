use actix_web::http::StatusCode;
use rv::error::ref_value_error::RefValueError;

#[test]
fn test_db_error_status_code() {
    let error = RefValueError::DbError("Database connection failed".to_string());
    assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_verify_error_status_code() {
    let error = RefValueError::VerifyError("Verification failed".to_string());
    assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_json_parse_error_status_code() {
    let error = RefValueError::JsonParseError("Invalid JSON format".to_string());
    assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_invalid_parameter_status_code() {
    let error = RefValueError::InvalidParameter("Missing required field".to_string());
    assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_signature_error_status_code() {
    let error = RefValueError::SignatureError("Invalid signature".to_string());
    assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_error_message_content() {
    let message = "Test error message";
    let error = RefValueError::DbError(message.to_string());
    match error {
        RefValueError::DbError(msg) => assert_eq!(msg, message),
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_db_error_message() {
    let error_msg = "Database connection failed";
    let error = RefValueError::DbError(error_msg.to_string());
    assert_eq!(error.message(), error.to_string());
    assert!(error.message().contains(error_msg));
}