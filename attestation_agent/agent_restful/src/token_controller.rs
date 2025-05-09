use actix_web::{HttpResponse, http::StatusCode};
use log::{error, info};
use serde_json::{json, Value};
use crate::response_error::create_error_response;
use challenge::token::{TokenManager, TokenRequest};
use challenge::challenge_error::ChallengeError;
use tokio::runtime::Runtime;
use std::thread;

// Asynchronous part of token processing
async fn process_token_request(token_request: TokenRequest) -> Result<serde_json::Value, ChallengeError> {
    match TokenManager::get_token(&token_request).await {
        Ok(token) => Ok(token),
        Err(error) => {
            error!("Failed to get token: {}", error);
            Err(ChallengeError::TokenError(error))
        }
    }
}

/// Main entry point for token requests
/// Handles both JSON request parsing and token generation
pub fn get_token(body: Option<Value>) -> HttpResponse {
    info!("Start getting token");

    // Parse and sanitize the request body, or use default if none provided
    let token_request = match body {
        Some(value) => match serde_json::from_value::<TokenRequest>(value) {
            Ok(req) => req.sanitize(),
            Err(e) => {
                return create_error_response(e, StatusCode::BAD_REQUEST);
            }
        },
        None => TokenRequest::default(),
    };

    let handle = thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(process_token_request(token_request))
    });
    
    match handle.join() {
        Ok(result) => match result {
            Ok(token) => HttpResponse::Ok().json(json!({ "token": token })),
            Err(error) => create_error_response(error, StatusCode::SERVICE_UNAVAILABLE),
        },
        Err(_) => create_error_response("Thread execution failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}
