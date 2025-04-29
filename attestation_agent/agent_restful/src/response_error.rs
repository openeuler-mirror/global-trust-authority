use actix_web::{HttpResponse, http::StatusCode};
use log::error;
use serde_json::json;

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
/// - For BAD_REQUEST (400), logs as request validation failure
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
