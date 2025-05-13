use std::collections::HashMap;

use actix_web::{web, HttpResponse};
use validator::Validate;
use common_log::info;
use crate::{
    constants::SERVICE_VERSION,
    entities::{attest_request::AttestRequest, token_response::TokenResponse},
    error::attestation_error::AttestationError,
    handler::standard_handler::StandardHandler,
};

pub struct AttestationService;

impl AttestationService {
    /// Process standard attestation request
    ///
    /// # Arguments
    /// * `request` - The attestation request containing measurements and evidence
    /// * `user_id` - The ID of the user making the request
    ///
    /// # Returns
    /// * `Result<HttpResponse, AttestationError>` - Returns HTTP response with tokens on success, or error on failure
    pub async fn process_standard_attestation(
        request: &web::Json<AttestRequest>,
        user_id: String,
    ) -> Result<HttpResponse, AttestationError> {
        if let Err(e) = request.validate() {
            return Err(AttestationError::InvalidParameter(e.to_string()));
        }
        info!("Start processing standard attestation request, user_id: {}", user_id);
        let nonce_type = request.nonce_type.as_deref().unwrap_or("default");
        info!("Using nonce type: {}", nonce_type);
        let mut token_list = Vec::new();
        for measurement in &request.measurements {
            info!("Start processing measurement, node_id: {}", measurement.node_id);
            // Validate nonce request
            StandardHandler::validate_nonce_request(measurement, nonce_type, &request).await?;
            info!("Nonce validation passed");
            let mut evidence_token_responses = HashMap::new();
            // Process each evidence
            for evidence in &measurement.evidences {
                let attester_type = &evidence.attester_type;
                let nonce_bytes =
                    StandardHandler::get_nonce_bytes(nonce_type, &measurement.nonce, request.user_nonce.as_ref())?;
                info!("Start verifying evidence, attester_type: {}", attester_type);
                // Verify evidence
                let verify_evidence = StandardHandler::verify_evidence(
                    &user_id,
                    Some(measurement.node_id.clone()),
                    evidence,
                    nonce_bytes,
                ).await?;
                info!("Evidence verification completed");
                // Evaluate export policy
                let raw_evidence = StandardHandler::evaluate_export_policy(&verify_evidence, attester_type)?;
                let mut verify_results = Vec::new();
                let mut evaluate_results = Vec::new();
                // Evaluate custom policies
                if let Some(policy_ids) = &evidence.policy_ids {
                    info!("Start evaluating custom policies, policy_ids: {:?}", policy_ids);
                    let (custom_verify_results, custom_evaluate_results) =
                        StandardHandler::evaluate_custom_policies(&verify_evidence, policy_ids).await?;
                    verify_results.extend(custom_verify_results);
                    evaluate_results = custom_evaluate_results;
                }
                // Create evidence response
                let evidence_token_response =
                    StandardHandler::create_evidence_response(verify_results, raw_evidence, evaluate_results);
                evidence_token_responses.insert(attester_type.to_string(), evidence_token_response);
            }
            // Create attestation response
            let attestation_response = StandardHandler::create_attestation_response(
                &evidence_token_responses,
                nonce_type,
                &measurement,
            );
            // Generate token
            let token = StandardHandler::generate_token(&attestation_response).await?;
            let token_response = TokenResponse { node_id: measurement.node_id.clone(), token };
            token_list.push(token_response);
            info!("Measurement processing completed, node_id: {}", measurement.node_id);
        }
        info!(
            "Standard attestation request processing completed, user_id: {}, tokens generated: {}",
            user_id,
            token_list.len()
        );
        // Return response
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "service_version": SERVICE_VERSION,
            "tokens": token_list
        })))
    }
}
