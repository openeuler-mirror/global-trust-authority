/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use std::collections::HashMap;

use actix_web::{web, HttpResponse};
use validator::Validate;
use common_log::info;
use crate::{
    constants::SERVICE_VERSION,
    entities::{attest_request::AttestRequest, token_response::TokenResponse},
    error::attestation_error::AttestationError,
    handler::default_handler::DefaultHandler,
};

pub struct AttestationService;

impl AttestationService {
    /// Process default attestation request
    ///
    /// # Arguments
    /// * `request` - The attestation request containing measurements and evidence
    /// * `user_id` - The ID of the user making the request
    ///
    /// # Returns
    /// * `Result<HttpResponse, AttestationError>` - Returns HTTP response with tokens on success, or error on failure
    /// 
    /// # Errors
    /// 
    /// * `AttestationError` - If the request is invalid or an error occurs during processing
    pub async fn process_default_attestation(
        request: &web::Json<AttestRequest>,
        user_id: String,
    ) -> Result<HttpResponse, AttestationError> {
        if let Err(e) = request.validate() {
            return Err(AttestationError::InvalidParameter(e.to_string()));
        }
        info!("Start processing default attestation request, user_id: {}", user_id);
        let nonce_type = request.nonce_type.as_deref().unwrap_or("default");
        info!("Using nonce type: {}", nonce_type);
        let mut token_list = Vec::new();
        for measurement in &request.measurements {
            info!("Start processing measurement, node_id: {}", measurement.node_id);
            // Validate nonce request
            DefaultHandler::validate_nonce_request(measurement, nonce_type, &request).await?;
            let mut evidence_token_responses = HashMap::new();
            // Process each evidence
            for evidence in &measurement.evidences {
                let attester_type = &evidence.attester_type;
                let nonce_bytes =
                    DefaultHandler::get_nonce_bytes(nonce_type, &measurement.nonce, request.user_nonce.as_ref())?;
                info!("Start verifying evidence, attester_type: {}", attester_type);
                // Verify evidence
                let verify_evidence = DefaultHandler::verify_evidence(
                    &user_id,
                    Some(measurement.node_id.clone()),
                    evidence,
                    nonce_bytes,
                ).await?;
                // Evaluate export policy
                let raw_evidence = DefaultHandler::evaluate_export_policy(&verify_evidence, attester_type)?;
                // Evaluate custom policies
                let (custom_verify_results, custom_evaluate_results) = DefaultHandler::evaluate_policies(
                    &verify_evidence,
                    evidence.policy_ids.as_ref(),
                    &attester_type
                ).await?;
                // Create evidence response
                let evidence_token_response =
                    DefaultHandler::create_evidence_response(custom_verify_results, raw_evidence, custom_evaluate_results);
                evidence_token_responses.insert(attester_type.to_string(), evidence_token_response);
            }
            // Create attestation response
            let attestation_response = DefaultHandler::create_attestation_response(
                &evidence_token_responses,
                nonce_type,
                &measurement,
            );
            // Generate token
            let token = DefaultHandler::generate_token(&attestation_response).await?;
            let token_response = TokenResponse { node_id: measurement.node_id.clone(), token };
            token_list.push(token_response);
            info!("Measurement processing completed, node_id: {}", measurement.node_id);
        }
        info!(
            "Default attestation request processing completed, user_id: {}, tokens generated: {}",
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
