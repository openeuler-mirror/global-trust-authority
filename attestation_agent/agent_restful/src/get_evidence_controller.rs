use actix_web::{HttpResponse, http::StatusCode};
use log::info;
use serde_json::Value;
use crate::response_error::create_error_response;
use challenge::evidence::{EvidenceManager, GetEvidenceRequest};

/// Main entry point for evidence collection requests
/// Processes the request and returns collected evidence
pub fn get_evidence(body: Option<Value>) -> HttpResponse {
    info!("Start collecting evidence");

    // Parse and sanitize the request body, or use default if none provided
    let evidence_request = match body {
        Some(value) => match serde_json::from_value::<GetEvidenceRequest>(value) {
            Ok(req) => req.sanitize(),
            Err(e) => {
                return create_error_response(e, StatusCode::BAD_REQUEST);
            }
        },
        None => GetEvidenceRequest::default(),
    };

    // Collect evidence and handle the response
    match EvidenceManager::get_evidence(&evidence_request) {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(error) => create_error_response(error, StatusCode::SERVICE_UNAVAILABLE),
    }
}