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

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::entities::token::token_trait::TokenType;
use base64::engine::general_purpose::STANDARD;
use common_log::{error, info};
use config_manager::types::context::CONFIG;
use nonce::nonce_interface::{validate_nonce, Nonce, ValidateNonceParams};
use openssl::sha::Sha256;
use plugin_manager::{PluginManager, PluginManagerInstance, ServiceHostFunctions, ServicePlugin};
use policy::api::{get_export_policy::get_export_policy, get_policy_by_ids, query_policy};
use policy_engine::evaluate_policy;
use rdb::get_connection;
use token_management::manager::TokenManager;

use crate::{
    entities::{
        attest_request::{Evidence, Measurement},
        token::PolicyInfo,
    },
    error::attestation_error::AttestationError,
};

pub struct DefaultHandler;

impl DefaultHandler {
    pub async fn validate_nonce_request(measurement: &Measurement) -> Result<(), AttestationError> {
        let nonce_type = measurement.nonce_type.as_ref().map_or("verifier", |s| s);
        info!("Starting nonce validation with type: {}", nonce_type);
        match nonce_type {
            "user" => {
                if measurement.nonce.is_none() {
                    error!("Nonce parameter required but not provided");
                    return Err(AttestationError::NonceVerificationError("nonce parameter required".into()));
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
        
        // Decode the base64 nonce string first
        let decoded_nonce = BASE64.decode(nonce).map_err(|e| {
            error!("Failed to decode base64 nonce: {}", e);
            AttestationError::NonceVerificationError(format!("failed to decode base64 nonce: {}", e))
        })?;
        
        // Convert the decoded bytes to a string
        let nonce_str = String::from_utf8(decoded_nonce).map_err(|e| {
            error!("Failed to convert nonce to string: {}", e);
            AttestationError::NonceVerificationError(format!("invalid nonce format: {}", e))
        })?;
        
        // Parse the JSON string into a Nonce struct
        let parsed_nonce: Nonce = serde_json::from_str(&nonce_str).map_err(|e| {
            error!("Failed to deserialize nonce: {}", e);
            AttestationError::NonceVerificationError(format!("invalid nonce format: {}", e))
        })?;

        // Replace the first occurrence
        info!("Validating nonce with period: {}", CONFIG.get_instance()?.attestation_service.nonce.nonce_valid_period);
        let validation_result = validate_nonce(ValidateNonceParams {
            // Replace the second occurrence
            valid_period: CONFIG.get_instance()?.attestation_service.nonce.nonce_valid_period,
            nonce: parsed_nonce,
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

    /// Generate aggregate nonce bytes from nonce and attester data
    ///
    /// # Arguments
    /// * `nonce` - Option containing nonce bytes
    /// * `attester_data` - Option containing attester data
    ///
    /// # Returns
    /// * `Option<Vec<u8>>` - Aggregate nonce bytes if both inputs are Some, otherwise None
    pub fn get_aggregate_nonce_bytes(
        nonce: &Option<Vec<u8>>,
        attester_data: &Option<serde_json::Value>,
    ) -> Option<Vec<u8>> {
        // If both inputs are None, return None
        if attester_data.is_none() && nonce.is_none() {
            return None;
        }

        // Create a new SHA-256 hasher
        let mut hasher = Sha256::new();

        // Update with nonce if it exists
        if let Some(nonce) = nonce {
            hasher.update(nonce);
        }

        // Update with attester_data if it exists
        if let Some(data) = attester_data {
            // Convert to string and then to bytes
            let data_str = data.to_string();
            // Base64 encode the string
            let base64_data = STANDARD.encode(&data_str);
            hasher.update(base64_data.as_bytes());
        }

        let result = hasher.finish();
        Some(result.to_vec())
    }

    pub fn get_nonce_bytes(nonce_type: &str, nonce: Option<&String>) -> Result<Option<Vec<u8>>, AttestationError> {
        match nonce_type {
            "user" | "verifier" => {
                if let Some(n) = nonce {
                    match BASE64.decode(n) {
                        Ok(bytes) => Ok(Some(bytes)),
                        Err(e) => {
                            error!("Failed to decode nonce: {}", e);
                            Err(AttestationError::NonceVerificationError(format!("failed to decode nonce: {}", e)))
                        },
                    }
                } else {
                    error!("Missing nonce");
                    Err(AttestationError::NonceVerificationError("missing nonce".into()))
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

        plugin.verify_evidence(user_id, node_id.as_deref(), &evidence.evidence, nonce_bytes.as_deref()).await.map_err(
            |e| {
                error!("Evidence verification failed: {}", e);
                AttestationError::EvidenceVerificationError(e.to_string())
            },
        )
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

    pub async fn evaluate_user_policies(
        verify_evidence: &serde_json::Value,
        policy_ids: Option<&Vec<String>>,
        attester_type: &str,
        token_fmt: &str,
        user_id: &str,
    ) -> Result<(Vec<bool>, Vec<PolicyInfo>), AttestationError> {
        let mut policy_id_list: Vec<String> = Vec::new();
        if let Some(ids) = policy_ids {
            policy_id_list = ids.clone();
        } else {
            info!("No policy_ids provided, using default policies for attester_type: {}", attester_type);
            let db_connection = get_connection().await.map_err(|e| {
                error!("Failed to get database connection: {}", e);
                AttestationError::DatabaseError(e.to_string())
            })?;
            match query_policy::get_default_policies_by_type(&db_connection, attester_type.to_string(), user_id).await {
                Ok(default_policies) => {
                    if !default_policies.is_empty() {
                        policy_id_list = default_policies.iter().map(|p| p.id.clone()).collect();
                    } else {
                        info!("No default policies found for attester_type: {}", attester_type);
                    }
                },
                Err(e) => {
                    error!("Failed to get default policies for attester_type {}: {}", attester_type, e);
                    return Err(AttestationError::DatabaseError(e.to_string()));
                },
            }
        }
        if token_fmt == "ear" && policy_id_list.len() > 1 {
            return Err(AttestationError::InvalidParameter("ear token only support one policy".to_string()));
        }
        let (verify_results, evaluate_results) =
            Self::evaluate_custom_policies(verify_evidence, &policy_id_list).await?;
        Ok((verify_results, evaluate_results))
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

    pub async fn generate_token(attestation_response: &TokenType) -> Result<String, AttestationError> {
        info!("Generating token for attestation response");

        match attestation_response {
            TokenType::Eat(eat_token) => {
                let mut json_body = serde_json::to_value(eat_token)
                    .map_err(|e| AttestationError::TokenGenerationError(e.to_string()))?;

                TokenManager::generate_token(&mut json_body).await.map_err(|e| {
                    error!("Failed to generate token: {}", e);
                    AttestationError::TokenGenerationError(e.to_string())
                })
            },
            TokenType::Ear(ear_token) => {
                let mut json_body = serde_json::to_value(ear_token)
                    .map_err(|e| AttestationError::TokenGenerationError(e.to_string()))?;

                TokenManager::generate_token(&mut json_body).await.map_err(|e| {
                    error!("Failed to generate token: {}", e);
                    AttestationError::TokenGenerationError(e.to_string())
                })
            },
        }
    }
}
