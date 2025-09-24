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

use crate::{
    constants::SERVICE_VERSION,
    entities::token::token_trait::Token,
    entities::{
        attest_request::{AttestRequest, Evidence, Measurement},
        token::token_trait::AttesterResult,
    },
    error::attestation_error::AttestationError,
    factory::TokenFactory,
    handler::default_handler::DefaultHandler,
};
use actix_web::{web, HttpResponse};
use common_log::info;
use serde::{Deserialize, Serialize};
use validator::Validate;

pub struct AttestationService;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub node_id: String,
    pub token: String,
}

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

        let token_list = Self::process_measurements(&request.measurements, &user_id).await?;

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

    /// Process all measurements in the attestation request
    async fn process_measurements(
        measurements: &[Measurement],
        user_id: &str,
    ) -> Result<Vec<TokenResponse>, AttestationError> {
        let mut token_list = Vec::new();

        for measurement in measurements {
            info!("Start processing measurement, node_id: {}", measurement.node_id);

            let token = Self::process_single_measurement(measurement, user_id).await?;
            token_list.push(TokenResponse {
                node_id: measurement.node_id.clone(),
                token,
            });

            info!("Measurement processing completed, node_id: {}", measurement.node_id);
        }

        Ok(token_list)
    }

    /// Process a single measurement
    async fn process_single_measurement(measurement: &Measurement, user_id: &str) -> Result<String, AttestationError> {
        // Validate nonce request
        DefaultHandler::validate_nonce_request(measurement).await?;

        // Process evidences and get both responses and the token instance
        let (evidence_token_responses, token_instance) = Self::process_evidences(measurement, user_id).await?;

        // Create attestation response using the same token instance that processed evidences
        let attestation_response = token_instance.create_attestation_response(
            &evidence_token_responses,
            &measurement.nonce_type.clone().unwrap_or("verifier".to_string()),
            &measurement.nonce,
            measurement,
        );

        // Generate token
        DefaultHandler::generate_token(&attestation_response).await
    }

    /// Process all evidences in a measurement
    async fn process_evidences(
        measurement: &Measurement,
        user_id: &str,
    ) -> Result<(HashMap<String, AttesterResult>, Box<dyn Token>), AttestationError> {
        let mut evidence_token_responses = HashMap::new();

        // Create token instance once and reuse it for all evidences
        let token_factory = TokenFactory::new();
        let mut token_instance = token_factory.create_token(measurement.token_fmt.as_deref().unwrap_or("eat"))?;

        for evidence in &measurement.evidences {
            let evidence_token_response =
                Self::process_single_evidence(evidence, measurement, user_id, &mut token_instance).await?;
            evidence_token_responses.insert(evidence.attester_type.to_string(), evidence_token_response);
        }

        Ok((evidence_token_responses, token_instance))
    }

    /// Process a single evidence
    async fn process_single_evidence(
        evidence: &Evidence,
        measurement: &Measurement,
        user_id: &str,
        token_instance: &mut Box<dyn Token>,
    ) -> Result<AttesterResult, AttestationError> {
        let attester_type = &evidence.attester_type;

        let nonce_bytes = DefaultHandler::get_nonce_bytes(
            &measurement.nonce_type.clone().unwrap_or("verifier".to_string()),
            measurement.nonce.as_ref(),
        )?;

        let aggregate_nonce_bytes = DefaultHandler::get_aggregate_nonce_bytes(&nonce_bytes, &measurement.attester_data);

        info!("Start verifying evidence, attester_type: {}", attester_type);

        // Verify evidence
        let verify_evidence = DefaultHandler::verify_evidence(
            user_id,
            Some(measurement.node_id.clone()),
            evidence,
            aggregate_nonce_bytes,
        )
        .await?;

        // Evaluate export policy
        let raw_evidence = DefaultHandler::evaluate_export_policy(&verify_evidence, attester_type)?;

        // Evaluate custom policies
        let (custom_verify_results, custom_evaluate_results) = DefaultHandler::evaluate_user_policies(
            &verify_evidence,
            evidence.policy_ids.as_ref(),
            attester_type,
            measurement.token_fmt.as_deref().unwrap_or("eat"),
            user_id,
        )
        .await?;

        // Create evidence response using the shared token instance
        Ok(token_instance.create_evidence_response(custom_verify_results, raw_evidence, custom_evaluate_results))
    }
}
