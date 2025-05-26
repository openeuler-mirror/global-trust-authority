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

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use config_manager::types::context::CONFIG;
use common_log::{error, info};
use nonce::nonce_interface::{validate_nonce, Nonce, ValidateNonceParams};
use plugin_manager::{PluginManager, PluginManagerInstance, ServiceHostFunctions, ServicePlugin};
use policy::policy_api::{get_export_policy::get_export_policy, get_policy_by_ids};
use policy_engine::evaluate_policy;
use rdb::get_connection;
use token_management::token_manager::TokenManager;

use crate::{
    entities::{
        attest_request::{AttestRequest, Evidence, Measurement, Nonce as AttestNonce},
        token_response::{AttestationResponse, AttesterResult, PolicyInfo},
    },
    error::attestation_error::AttestationError,
};

pub struct StandardHandler;

impl StandardHandler {
    pub async fn validate_nonce_request(
        measurement: &Measurement,
        nonce_type: &str,
        request: &AttestRequest,
    ) -> Result<(), AttestationError> {
        info!("Starting nonce validation with type: {}", nonce_type);
        match nonce_type {
            "user" => {
                if request.user_nonce.is_none() {
                    error!("User nonce parameter required but not provided");
                    return Err(AttestationError::NonceVerificationError("user_nonce parameter required".into()));
                }
                return Ok(());
            },
            "ignore" => return Ok(()),
            _ => {},
        }

        let nonce = measurement.nonce.as_ref().ok_or_else(|| {
            error!("Missing nonce in measurements");
            AttestationError::NonceVerificationError("missing nonce in measurements".into())
        })?;

        // Replace the first occurrence
        info!(
            "Validating nonce with period: {}",
            CONFIG.get_instance()?.attestation_service.nonce.nonce_valid_period
        );
        let validation_result = validate_nonce(ValidateNonceParams {
            // Replace the second occurrence
            valid_period: CONFIG.get_instance()?.attestation_service.nonce.nonce_valid_period,
            nonce: Nonce { iat: nonce.iat, value: nonce.value.clone(), signature: nonce.signature.clone() },
        })
        .await;

        if !validation_result.is_valid {
            error!("Nonce validation failed: {}", validation_result.message);
            return Err(AttestationError::NonceVerificationError(validation_result.message));
        }

        Ok(())
    }

    pub fn get_plugin_use_attester_type(attester_type: &String) -> Result<Arc<dyn ServicePlugin>, AttestationError> {
        match PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance().get_plugin(attester_type) {
            Some(plugin) => Ok(plugin),
            None => Err(AttestationError::PluginNotFoundError({
                error!("Plugin not found for attester type: {}", attester_type);
                format!("Plugin not found for attester type: {}", attester_type)
            })),
        }
    }

    pub fn get_nonce_bytes(
        nonce_type: &str,
        nonce: &Option<AttestNonce>,
        user_nonce: Option<&String>,
    ) -> Result<Option<Vec<u8>>, AttestationError> {
        match nonce_type {
            "default" => {
                if let Some(n) = nonce {
                    Ok(Some(n.value.clone().into_bytes()))
                } else {
                    error!("Missing nonce for default type");
                    Err(AttestationError::NonceVerificationError("missing nonce for default type".into()))
                }
            },
            "user" => {
                if let Some(un) = user_nonce {
                    match BASE64.decode(un) {
                        Ok(bytes) => Ok(Some(bytes)),
                        Err(e) => {
                            error!("Failed to decode user_nonce: {}", e);
                            Err(AttestationError::NonceVerificationError(format!("failed to decode user_nonce: {}", e)))
                        },
                    }
                } else {
                    error!("Missing user_nonce");
                    Err(AttestationError::NonceVerificationError("missing user_nonce".into()))
                }
            },
            "ignore" => Ok(None),
            _ => {
                error!("Invalid nonce_type: {}", nonce_type);
                Err(AttestationError::NonceVerificationError(format!("invalid nonce_type: {}", nonce_type)))
            },
        }
    }

    pub async fn verify_evidence(
        user_id: &str,
        node_id: Option<String>,
        evidence: &Evidence,
        nonce_bytes: Option<Vec<u8>>,
    ) -> Result<serde_json::Value, AttestationError> {
        info!("Starting evidence verification for user: {}, node: {:?}", user_id, node_id);
        let attester_type = &evidence.attester_type;
        let plugin = Self::get_plugin_use_attester_type(attester_type)?;

        plugin.verify_evidence(user_id, node_id.as_deref(), &evidence.evidence, nonce_bytes.as_deref())
            .await
            .map_err(|e| {
                error!("Evidence verification failed: {}", e);
                AttestationError::EvidenceVerificationError(e.to_string())
            })
    }

    pub fn evaluate_export_policy(
        verify_evidence: &serde_json::Value,
        attester_type: &str,
    ) -> Result<Option<serde_json::Value>, AttestationError> {
        info!("Evaluating export policy for attester type: {}", attester_type);
        let export_policy = match get_export_policy(attester_type) {
            Ok(policy) => policy,
            Err(e) => {
                error!("Failed to get export policy for attester type: {}, error: {}", attester_type, e);
                return Err(AttestationError::PolicyNotFoundError(e.to_string()));
            },
        };

        match evaluate_policy(verify_evidence, &export_policy) {
            Ok(result) => {
                if result == serde_json::json!({}) {
                    Ok(None)
                } else {
                    Ok(Some(result))
                }
            },
            Err(e) => {
                error!("Failed to evaluate export policy: {}", e);
                Err(AttestationError::PolicyVerificationError(e.to_string()))
            },
        }
    }

    pub async fn evaluate_custom_policies(
        verify_evidence: &serde_json::Value,
        policy_ids: &[String],
    ) -> Result<(Vec<bool>, Vec<PolicyInfo>), AttestationError> {
        info!("Evaluating custom policies, count: {}", policy_ids.len());
        let mut verify_results = Vec::new();
        let mut evaluate_results = Vec::new();

        let db_connection = get_connection().await.unwrap();
        let policies = match get_policy_by_ids(&db_connection, policy_ids.to_vec()).await {
            Ok(policies) => policies,
            Err(e) => {
                error!("Failed to get policies by ids: {}", e);
                return Err(AttestationError::PolicyNotFoundError(e.to_string()));
            },
        };

        for policy in policies {
            let evaluate_result = match evaluate_policy(verify_evidence, &policy.content) {
                Ok(result) => {
                    let policy_matched = result.get("policy_matched").and_then(|v| v.as_bool()).ok_or_else(|| {
                        let err_msg = format!(
                            "Failed to extract boolean 'policy_matched' from policy evaluation result for policy {}",
                            policy.id
                        );
                        error!("{}", err_msg);
                        AttestationError::PolicyVerificationError(err_msg)
                    })?;

                    verify_results.push(policy_matched);
                    PolicyInfo {
                        appraisal_policy_id: policy.id.clone(),
                        policy_version: policy.version,
                        policy_matched,
                        custom_data: result.get("custom_data").map(|v| v.clone()),
                    }
                },
                Err(e) => {
                    error!("Policy evaluation failed for policy {}: {}", policy.id, e);
                    return Err(AttestationError::PolicyVerificationError(format!(
                        "Policy evaluation failed for policy {}: {}",
                        policy.id, e
                    )));
                },
            };
            evaluate_results.push(evaluate_result);
        }

        Ok((verify_results, evaluate_results))
    }

    pub fn create_evidence_response(
        verify_results: Vec<bool>,
        raw_evidence: Option<serde_json::Value>,
        policy_info: Vec<PolicyInfo>,
    ) -> AttesterResult {
        let attestation_status = if policy_info.is_empty() {
            "unknown"
        } else if verify_results.iter().all(|&x| x) {
            "pass"
        } else {
            "fail"
        };

        AttesterResult { attestation_status: attestation_status.to_string(), raw_evidence, policy_info }
    }

    pub fn create_attestation_response(
        evidence_token_responses: &HashMap<String, AttesterResult>,
        nonce_type: &str,
        measurement: &Measurement,
    ) -> AttestationResponse {
        AttestationResponse {
            eat_nonce: if nonce_type == "default" { measurement.nonce.clone() } else { None },
            attester_data: measurement.attester_data.clone(),
            results: evidence_token_responses.clone(),
            intuse: Some("Generic".to_string()),
            ueid: Some(measurement.node_id.clone()),
        }
    }

    pub async fn generate_token(attestation_response: &AttestationResponse) -> Result<String, AttestationError> {
        info!("Generating token for attestation response");
        let mut json_body = serde_json::to_value(attestation_response)
            .map_err(|e| AttestationError::TokenGenerationError(e.to_string()))?;

        TokenManager::generate_token(&mut json_body).await.map_err(|e| {
            error!("Failed to generate token: {}", e);
            AttestationError::TokenGenerationError(e.to_string())
        })
    }
}
