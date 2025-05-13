use actix_web::{web, HttpResponse};
use log::{error, info};
use serde::Deserialize;
use token_management::token_manager::TokenManager;

/// token controller

/// verify token request parameter
#[derive(Deserialize)]
pub struct TokenRequest {
    token: String,
}

/// verify token restful
pub async fn verify_token(token_req: web::Json<TokenRequest>) -> HttpResponse {
    info!("Start verifying token");
    let token = &token_req.token;

    if token.is_empty() {
        error!("Token is empty");
        return HttpResponse::BadRequest().body("Token is empty");
    }
    match TokenManager::verify_token(token).await {
        Ok(verify_token_response) => HttpResponse::Ok().json(verify_token_response),
        Err(verify_token_error) => HttpResponse::ServiceUnavailable().body(verify_token_error.to_string())
    }
}