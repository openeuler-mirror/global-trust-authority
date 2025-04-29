use actix_web::{web, HttpRequest};
use crate::entities::attest_request::AttestRequest;
use crate::strategy::attestation_strategy::AttestationStrategy;
use crate::strategy::attestation_strategy::AttestFuture;
use crate::service::attest_service::AttestationService;

pub struct StandardAttestationStrategy {}

impl StandardAttestationStrategy {
    pub fn new() -> Self {
        Self {}
    }
}

impl AttestationStrategy for StandardAttestationStrategy {
    fn attest<'a>(&'a self, request: &'a web::Json<AttestRequest>, http_req: &'a HttpRequest) -> AttestFuture<'a> {
        let user_id = http_req.headers().get("User-Id").and_then(|h| h.to_str().ok()).unwrap_or_default().to_string();
        Box::pin(async move {
            AttestationService::process_standard_attestation(request, user_id).await
        })
    }
}