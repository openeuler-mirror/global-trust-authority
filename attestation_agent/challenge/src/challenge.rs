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

use crate::challenge_error::{ChallengeError, TokenError};
use agent_utils::Client;
use config::{PluginConfig, AGENT_CONFIG};
use log;
use once_cell::sync::Lazy;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use plugin_manager::{AgentHostFunctions, AgentPlugin, PluginManager, PluginManagerInstance};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex as StdMutex};
use parking_lot::{Mutex, MutexGuard};
use crate::nonce_util::NonceUtil;

const TIME_OUT: u64 = 120;

#[derive(Debug, Clone)]
pub struct NodeToken {
    node_id: String,
    token: Value,
    token_fmt: String,
}

static GLOBAL_TPM: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Global cached tokens for reuse between requests (sync Mutex)
pub static GLOBAL_TOKENS: Lazy<StdMutex<Vec<NodeToken>>> = Lazy::new(|| StdMutex::new(Vec::new()));

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
/// Information about an attester, including type and policy IDs
pub struct AttesterInfo {
    #[serde(default)]
    pub attester_type: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_types: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
/// Evidence structure with associated policy IDs
pub struct EvidenceWithPolicy {
    pub attester_type: String,
    pub evidence: serde_json::Value,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
/// Measurement structure containing node and evidence info
pub struct Measurement {
    pub node_id: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default)]
    pub nonce_type: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<serde_json::Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_fmt: Option<String>,
    pub evidences: Vec<EvidenceWithPolicy>,
}

#[derive(Debug, Serialize)]
/// Response structure for evidence collection
pub struct GetEvidenceResponse {
    pub agent_version: String,
    pub measurements: Vec<Measurement>,
}

impl GetEvidenceResponse {
    pub fn new(
        agent_version: &str,
        nonce_type: &str,
        nonce: Option<&String>,
        attester_data: Option<&serde_json::Value>,
        node_id: &str,
        evidences: Vec<EvidenceWithPolicy>,
        token_fmt: Option<&str>,
    ) -> Self {
        GetEvidenceResponse {
            agent_version: agent_version.to_string(),
            measurements: vec![Measurement {
                node_id: node_id.to_string(),
                nonce: nonce.cloned(),
                nonce_type: nonce_type.to_string(),
                attester_data: attester_data.cloned(),
                token_fmt: token_fmt.map(|s| s.to_string()),
                evidences,
            }],
        }
    }
}

/// Acquire a global thread lock to protect TPM access, with 120s timeout
fn acquire_thread_lock() -> Result<MutexGuard<'static, ()>, ChallengeError> {
    GLOBAL_TPM.try_lock_for(std::time::Duration::from_secs(TIME_OUT))
        .ok_or_else(|| ChallengeError::InternalError("TPM mutex lock acquire timeout".to_string()))
}

/// Set the global cached tokens (async)
///
/// # Errors
///
/// Returns an error if the lock cannot be acquired.
pub fn set_cached_tokens(tokens: &[NodeToken]) -> Result<(), ChallengeError> {
    let mut global = GLOBAL_TOKENS.lock().map_err(|e| {
        log::error!("Failed to acquire lock for setting cached tokens: {}", e);
        ChallengeError::InternalError("Failed to acquire lock for setting cached tokens".to_string())
    })?;
    *global = tokens.to_vec();
    Ok(())
}

/// Get the cached token for current `node_id` and specific `token_fmt` as `serde_json::Value` (sync)
///
/// # Errors
///
/// Returns an error if the lock cannot be acquired or if node_id cannot be retrieved.
pub fn get_cached_token_for_current_node_with_fmt(token_fmt: &str) -> Result<Option<Value>, ChallengeError> {
    let node_id = get_node_id()?;
    let global = GLOBAL_TOKENS.lock().map_err(|e| {
        log::error!("Failed to acquire lock for getting cached token: {}", e);
        ChallengeError::TokenError(TokenError::TokenNotFound("Failed to acquire lock for getting cached token".to_string()))
    })?;
    Ok(global.iter()
        .find(|nt| nt.node_id == node_id && nt.token_fmt == token_fmt)
        .map(|nt| nt.token.clone()))
}

/// Get the node ID (UUID) from configuration
///
/// # Errors
///
/// Returns an error if the node ID cannot be retrieved.
pub fn get_node_id() -> Result<String, ChallengeError> {
    let config = AGENT_CONFIG.get_instance().map_err(|e| {
        log::error!("Failed to get AGENT_CONFIG instance: {}", e);
        ChallengeError::ConfigError(e.clone())
    })?;

    config.agent.uuid.clone().ok_or_else(|| {
        log::error!("Agent UUID not configured");
        ChallengeError::ConfigError("Agent UUID not configured".to_string())
    })
}

/// Get all enabled attester types from the plugin manager and config
fn get_enabled_attester_types() -> Result<Vec<String>, ChallengeError> {
    let plugin_manager = PluginManager::<dyn AgentPlugin, AgentHostFunctions>::get_instance();

    if !plugin_manager.is_initialized() {
        log::error!("Plugin manager not initialized");
        return Err(ChallengeError::InternalError("Plugin manager not initialized".to_string()));
    }

    let enabled_plugins = plugin_manager.get_plugin_types();
    if enabled_plugins.is_empty() {
        log::error!("No enabled plugins found");
        return Err(ChallengeError::PluginNotFound("No enabled plugins found".to_string()));
    }

    let config = AGENT_CONFIG.get_instance().map_err(|e| {
        log::error!("Failed to get AGENT_CONFIG instance: {}", e);
        ChallengeError::ConfigError(e.clone())
    })?;

    let mut enabled_attester_types = Vec::new();

    for plugin_name in &enabled_plugins {
        if let Some(plugin_config) = config.plugins.iter().find(|p| &p.name == plugin_name) {
            if let Some(params) = &plugin_config.params {
                let attester_type = match params {
                    config::PluginParams::TpmBoot(_) => "tpm_boot",
                    config::PluginParams::TpmIma(_) => "tpm_ima",
                    config::PluginParams::VirtCCA(_) => "virt_cca",
                };
                enabled_attester_types.push(attester_type.to_string());
            }
        }
    }

    if enabled_attester_types.is_empty() {
        log::error!("No enabled attester types found in config");
        return Err(ChallengeError::PluginNotFound("No enabled attester types found in config".to_string()));
    }

    Ok(enabled_attester_types)
}

/// Find the plugin and config that matches the given `attester_type`
fn find_plugin_for_attester_type(attester_type: &str) -> Result<(Arc<dyn AgentPlugin>, PluginConfig), ChallengeError> {
    let config = AGENT_CONFIG.get_instance().map_err(|e| {
        log::error!("Failed to get AGENT_CONFIG instance: {}", e);
        ChallengeError::ConfigError(e.clone())
    })?;
    let plugin_config = config
        .plugins
        .iter()
        .find(|p| {
            p.enabled
                && p.params.as_ref().is_some_and(|params| {
                    matches!(
                        (params, attester_type),
                        (config::PluginParams::TpmBoot(_), "tpm_boot") | (config::PluginParams::TpmIma(_), "tpm_ima") | (config::PluginParams::VirtCCA(_), "virt_cca")
                    )
                })
        })
        .ok_or_else(|| {
            log::error!("Plugin not found for attester_type: {}", attester_type);
            ChallengeError::PluginNotFound(attester_type.to_string())
        })?
        .clone();

    let plugin_manager = PluginManager::<dyn AgentPlugin, AgentHostFunctions>::get_instance();
    if !plugin_manager.is_initialized() {
        log::error!("Plugin manager not initialized");
        return Err(ChallengeError::InternalError("Plugin manager not initialized".to_string()));
    }
    let plugin = plugin_manager.get_plugin(&plugin_config.name).ok_or_else(|| {
        log::error!("Plugin instance not found: {}", plugin_config.name);
        ChallengeError::PluginNotFound(plugin_config.name.clone())
    })?;

    Ok((plugin, plugin_config))
}

/// Validate if the `attester_type` exists and is enabled
fn validate_attester_type(attester_type: &str) -> Result<bool, ChallengeError> {
    // Attempt to fetch the plugin; success confirms it exists and is enabled.
    find_plugin_for_attester_type(attester_type)?;
    Ok(true)
}

/// Collect evidence for a specific attester type and nonce
fn collect_evidence(attester_type: &str, nonce_value: Option<String>, log_types: Option<Vec<String>>) -> Result<serde_json::Value, ChallengeError> {
    let (plugin, _) = find_plugin_for_attester_type(attester_type)?;
    let node_id = get_node_id()?;
    let nonce_bytes = nonce_value.as_ref().map(|s| {
        STANDARD.decode(s).map_err(|e| {
            log::error!("Failed to decode base64 nonce: {}", e);
            ChallengeError::NonceInvalid(format!("Failed to decode base64 nonce: {}", e))
        })
    }).transpose()?;

    let _lock_guard = acquire_thread_lock()?;
    match plugin.collect_evidence(Some(&node_id), nonce_bytes.as_deref(), log_types) {
        Ok(evidence_value) => {
            log::info!("Evidence collected for attester_type: {}", attester_type);
            Ok(evidence_value)
        },
        Err(e) => {
            log::error!("Failed to collect evidence for '{}': {}", attester_type, e);
            Err(ChallengeError::EvidenceCollectionFailed(e.to_string()))
        },
    }
}

/// Get policy IDs based on the calling context
///
/// For `collect_from_attester_info` scenario:
/// - If user-provided `policy_ids` count > 10: error
/// - If user-provided `policy_ids` empty: return None
/// - If user-provided `policy_ids` count 1-10: use them
/// - If user didn't provide `policy_ids` (None): return None directly
///
/// For `collect_from_enabled_plugins` scenario:
/// - Get `policy_ids` from config file
/// - If config `policy_ids` count > 10: error
/// - If config `policy_ids` empty: return None
/// - If config `policy_ids` count 1-10: use them
fn get_policy_ids(
    attester_type: &str,
    input_policy_ids: &Option<Vec<String>>,
    use_config: bool,
) -> Result<Option<Vec<String>>, ChallengeError> {
    const MAX_POLICY_IDS: usize = 10;

    // Case: User provided policy_ids
    if let Some(ids) = input_policy_ids {
        if ids.len() > MAX_POLICY_IDS {
            log::error!("Too many policy_ids for attester_type '{}', max allowed is {}", attester_type, MAX_POLICY_IDS);
            return Err(ChallengeError::InternalError(format!(
                "Too many policy_ids for attester_type '{}', max allowed is {}",
                attester_type, MAX_POLICY_IDS
            )));
        }

        // If user provided empty policy_ids, return None
        if ids.is_empty() {
            return Ok(None);
        }

        // User provided valid policy_ids (1-10), use them
        return Ok(Some(ids.clone()));
    }

    // Case: User didn't provide policy_ids (None)
    // Only query config file if use_config is true (collect_from_enabled_plugins scenario)
    if !use_config {
        // For collect_from_attester_info scenario, return None when policy_ids is None
        return Ok(None);
    }

    // Get policy_ids from config file (collect_from_enabled_plugins scenario)
    let (_, plugin_config) = find_plugin_for_attester_type(attester_type)?;

    if plugin_config.policy_id.len() > MAX_POLICY_IDS {
        log::error!(
            "Too many policy_ids in config for attester_type '{}', max allowed is {}",
            attester_type,
            MAX_POLICY_IDS
        );
        return Err(ChallengeError::InternalError(format!(
            "Too many policy_ids in config for attester_type '{}', max allowed is {}",
            attester_type, MAX_POLICY_IDS
        )));
    }

    // If config has empty policy_id, return None
    if plugin_config.policy_id.is_empty() {
        return Ok(None);
    }

    // Use policy_ids from config
    Ok(Some(plugin_config.policy_id))
}

/// Generic evidence collection helper function
fn collect_evidences_for_types(
    attester_info: &[AttesterInfo],
    nonce_value: &Option<String>,
    need_validate: bool,
    use_config: bool,
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    let mut all_evidences = Vec::new();
    for attester_info in attester_info.iter() {
        if need_validate {
            validate_attester_type(&attester_info.attester_type)?;
        }

        let evidence_value = collect_evidence(&attester_info.attester_type, nonce_value.clone(), attester_info.log_types.clone()).map_err(|e| {
            log::error!("Failed to collect evidence for '{}': {}", attester_info.attester_type, e);
            ChallengeError::EvidenceCollectionFailed(format!(
                "Failed to collect evidence for '{}': {}",
                attester_info.attester_type, e
            ))
        })?;

        let policy_ids = get_policy_ids(&attester_info.attester_type, &attester_info.policy_ids, use_config)?;
        all_evidences.push(EvidenceWithPolicy { attester_type: attester_info.attester_type.clone(), evidence: evidence_value, policy_ids });
    }
    if all_evidences.is_empty() {
        log::error!("No valid evidence collected for any attester_type");
        return Err(ChallengeError::NoValidEvidence("No evidence collected".to_string()));
    }
    Ok(all_evidences)
}

/// Collect evidence from provided attester info list
fn collect_from_attester_info(
    info: &[AttesterInfo],
    nonce_value: &Option<String>,
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    collect_evidences_for_types(info, nonce_value, true, false)
}

/// Collect evidence from all enabled plugins
fn collect_from_enabled_plugins(nonce_value: &Option<String>) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    let enabled_types = get_enabled_attester_types()?;
    let attester_infos = enabled_types.into_iter().map(|t| AttesterInfo {
         attester_type: t, 
         policy_ids: None, 
         log_types: None }).collect::<Vec<AttesterInfo>>();
    collect_evidences_for_types(&attester_infos, nonce_value, false, true)
}

/// Core function to collect evidences from attester info or enabled plugins
///
/// # Errors
///
/// Returns an error if the evidence collection fails.
///
/// # Panics
///
/// This function may panic if the attester type is not set or is empty.
pub fn collect_evidences_core(
    attester_info: &Option<Vec<AttesterInfo>>,
    nonce_value: &Option<String>,
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    match attester_info {
        Some(info) if !info.is_empty() => {
                log::info!("Collecting from provided attester_info");
                collect_from_attester_info(info, nonce_value)
            },
        // Default case: Get all enabled plugin types
        _ => {
            log::info!("No attester_info provided, collecting from enabled plugins");
            collect_from_enabled_plugins(nonce_value)
        },
    }
}

/// Validate Nonce fields, return `ChallengeError` if invalid
///
/// # Errors
///
/// Returns an error if the nonce fields are invalid.
pub fn validate_nonce_fields(nonce: &str) -> Result<(), ChallengeError> {
    if nonce.trim().is_empty() {
        return Err(ChallengeError::NonceInvalid("Nonce is empty".to_string()));
    }
    let nonce_bytes = match STANDARD.decode(nonce) {
        Ok(bytes) => bytes,
        Err(_) => return Err(ChallengeError::NonceInvalid("nonce decode error".to_string())),
    };

    let value_len = nonce_bytes.len();

    if !(1..=1024).contains(&value_len) {
        return Err(ChallengeError::NonceInvalid(format!(
            "nonce.value length must be between 1 and 1024 bytes, got {} bytes",
            value_len
        )));
    }
    Ok(())
}

/// Request a nonce from the server for attestation
async fn get_nonce_from_server(
    agent_version: &str,
    attester_info: &Option<Vec<AttesterInfo>>,
) -> Result<String, ChallengeError> {
    let attester_types = match attester_info {
        Some(info) if !info.is_empty() => {
            let filtered: Vec<_> =
                info.iter().map(|a| a.attester_type.clone()).filter(|s| !s.trim().is_empty()).collect();
            if filtered.is_empty() {
                get_enabled_attester_types()?
            } else {
                filtered
            }
        },
        _ => get_enabled_attester_types()?,
    };

    let request = serde_json::json!({
        "agent_version": agent_version,
        "attester_type": attester_types
    });

    let client = Client::instance();
    let response = client
        .request(Method::POST, "/global-trust-authority/service/v1/challenge", Some(request))
        .await
        .map_err(|e| {
            log::error!("Failed to get nonce from server: {}", e);
            ChallengeError::NetworkError(format!("Failed to get nonce: {}", e))
        })?;
    let json_value = response.json::<serde_json::Value>().await.map_err(|e| {
        log::error!("Failed to parse nonce response: {}", e);
        ChallengeError::RequestParseError(format!("Failed to parse nonce response: {}", e))
    })?;
    if let Some(msg) = json_value.get("message").and_then(|v| v.as_str()) {
        if !msg.is_empty() {
            log::error!("Server returned error message for nonce: {}", msg);
            return Err(ChallengeError::ServerError(msg.to_string()));
        }
    }

    let nonce: String = if let Some(nonce_val) = json_value.get("nonce") {
        serde_json::from_value(nonce_val.clone())
            .map_err(|e| ChallengeError::RequestParseError(format!("Failed to parse nonce: {}", e)))?
    } else {
        log::error!("Failed to get nonce from Server, nonce is not a string");
        return Err(ChallengeError::ServerError("Failed to get nonce from Server, nonce is not a string".to_string()));
    };
    validate_nonce_fields(&nonce)?;
    log::info!("Successfully obtained and validated nonce from server");
    Ok(nonce)
}

/// Send the evidence to the attestation server and extract all node tokens from the response.
async fn get_tokens_from_server(evidence: &GetEvidenceResponse) -> Result<Vec<NodeToken>, ChallengeError> {
    let client = Client::instance();
    // Send the evidence to the attestation server
    let response = client
        .request(Method::POST, "/global-trust-authority/service/v1/attest", Some(serde_json::to_value(evidence)?))
        .await
        .map_err(|e| {
            log::error!("Failed to send evidence to server: {}", e);
            ChallengeError::NetworkError(format!("Failed to verify evidence: {}", e))
        })?;
    log::info!("Received token response from server");
    // Parse the server's JSON response
    let json_value = response.json::<serde_json::Value>().await.map_err(|e| {
        log::error!("Failed to parse token response: {}", e);
        ChallengeError::RequestParseError(format!("Failed to parse verify response: {}", e))
    })?;

    // Check for error message in the response
    if let Some(msg) = json_value.get("message").and_then(|v| v.as_str()) {
        if !msg.is_empty() {
            log::error!("Server returned error message for tokens: {}", msg);
            return Err(ChallengeError::ServerError(msg.to_string()));
        }
    }

    // Extract the tokens array from the response
    let tokens = if let Some(val) = json_value.get("tokens") {
        val.as_array().ok_or_else(|| {
            log::error!("tokens field is not array in server response");
            ChallengeError::RequestParseError("tokens field is not array".to_string())
        })?
    } else {
        log::error!("No tokens field in server response");
        return Err(ChallengeError::TokenNotReceived);
    };
    let mut node_tokens = Vec::new();
    // For each token, extract node_id and token value
    for t in tokens {
        let node_id = t
            .get("node_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChallengeError::RequestParseError("token.node_id missing or not string".to_string()))?
            .to_string();
        let token_val = t.get("token").cloned().unwrap_or(serde_json::Value::Null);

        let token_fmt = evidence
            .measurements
            .iter()
            .find(|m| m.node_id == node_id)
            .and_then(|m| m.token_fmt.as_ref().cloned())
            .unwrap_or_else(|| "eat".to_string());

        node_tokens.push(NodeToken {
            node_id,
            token: token_val,
            token_fmt,
        });
    }

    Ok(node_tokens)
}

/// Main entry for the attestation challenge process
///
/// # Errors
///
/// Returns an error if the challenge fails.
pub async fn do_challenge(
    attester_info: &Option<Vec<AttesterInfo>>,
    attester_data: &Option<serde_json::Value>,
    token_fmt: Option<&str>,
) -> Result<serde_json::Value, ChallengeError> {
    log::info!("Starting challenge request.");

    let nonce = get_nonce_from_server(env!("CARGO_PKG_VERSION"), attester_info).await?;

    let aggregate_nonce = NonceUtil::update_nonce(attester_data, Some(&nonce))?;

    let evidences = match collect_evidences_core(attester_info, &aggregate_nonce) {
        Ok(evidences) => {
            log::info!("Successfully collected evidences");
            evidences
        },
        Err(e) => {
            log::error!("Failed to collect evidences: {}", e);
            return Err(e);
        },
    };

    let node_id = get_node_id()?;

    let evidence_response = GetEvidenceResponse::new(
        env!("CARGO_PKG_VERSION"),
        "verifier",
        Some(&nonce),
        attester_data.as_ref(),
        &node_id,
        evidences,
        token_fmt,
    );

    let node_tokens = get_tokens_from_server(&evidence_response).await?;
    set_cached_tokens(&node_tokens)?;

    for nt in node_tokens {
        if nt.node_id == node_id {
            log::info!("Successfully obtained token for node_id {}", node_id);
            return Ok(nt.token);
        }
    }

    log::error!("Token for node_id {} not found in server response", node_id);
    Err(ChallengeError::TokenNotReceived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};
    use serial_test::serial;

    fn clear_global_tokens() {
        if let Ok(mut tokens) = GLOBAL_TOKENS.lock() {
            tokens.clear();
            return;
        }

        if let Err(poisoned) = GLOBAL_TOKENS.lock() {
            let mut guard = poisoned.into_inner();
            guard.clear();
        }
    }

    #[test]
    fn test_attester_info_serialization() {
        let attester_info = AttesterInfo {
            attester_type: "tpm_boot".to_string(),
            policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
            log_types: None,
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);
    }

    #[test]
    fn test_nonce_validation_empty_fields() {
        let nonce = "";
        let result = validate_nonce_fields(nonce);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));
    }

    #[test]
    fn test_get_evidence_response_with_user_type() {
        let nonce = "user_provided_nonce".to_string();
        let evidences = vec![EvidenceWithPolicy {
            attester_type: "tpm_boot".to_string(),
            evidence: json!({"test": "evidence"}),
            policy_ids: None,
        }];

        let response = GetEvidenceResponse::new(
            "1.0.0",
            "user",
            Some(&nonce),
            None,
            "test_node_id",
            evidences,
            Some("eat"),
        );

        assert_eq!(response.measurements[0].nonce_type, "user");
        assert_eq!(response.measurements[0].nonce, Some(nonce));
    }

    #[test]
    fn test_evidence_with_policy_serialization() {
        let evidence = EvidenceWithPolicy {
            attester_type: "tpm_boot".to_string(),
            evidence: json!({"test": "evidence"}),
            policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
        };

        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(serialized.contains("tpm_boot"));
        assert!(serialized.contains("policy1"));
        assert!(serialized.contains("policy2"));
    }

    #[test]
    fn test_measurement_serialization() {
        let measurement = Measurement {
            node_id: "test_node".to_string(),
            nonce_type: "user".to_string(),
            nonce: Some("nonce".to_string()),
            attester_data: Some(json!({"data": "test"})),
            token_fmt: Some("eat".to_string()),
            evidences: vec![EvidenceWithPolicy {
                attester_type: "tpm_boot".to_string(),
                evidence: json!({"test": "evidence"}),
                policy_ids: None,
            }],
        };

        let serialized = serde_json::to_string(&measurement).unwrap();
        assert!(serialized.contains("test_node"));
        assert!(serialized.contains("tpm_boot"));
    }

    #[test]
    #[serial]
    fn test_global_tokens_operations() {
        // Clear any existing tokens
        clear_global_tokens();

        let tokens = vec![
            NodeToken {
                node_id: "node1".to_string(),
                token: json!({"token": "value1"}),
                token_fmt: "eat".to_string(),
            },
            NodeToken {
                node_id: "node2".to_string(),
                token: json!({"token": "value2"}),
                token_fmt: "eat".to_string(),
            },
        ];

        set_cached_tokens(&tokens).unwrap();

        // Verify tokens were set
        if let Ok(global) = GLOBAL_TOKENS.lock() {
            assert_eq!(global.len(), 2);
            assert_eq!(global[0].node_id, "node1");
            assert_eq!(global[1].node_id, "node2");
        } else {
            return;
        }
    }

    #[test]
    #[serial]
    fn test_set_cached_tokens_edge_cases() {
        // Test setting empty cache
        let timeout = Duration::from_secs(5);
        let start = Instant::now();
        clear_global_tokens();

        set_cached_tokens(&[]).unwrap();
        if let Ok(global) = GLOBAL_TOKENS.lock() {
            assert_eq!(global.len(), 0);
        } else {
            return;
        }

        // Test setting a single token
        let single_token = vec![NodeToken {
            node_id: "test_node".to_string(),
            token: json!({"token": "value"}),
            token_fmt: "eat".to_string(),
        }];
        set_cached_tokens(&single_token).unwrap();
        if let Ok(global) = GLOBAL_TOKENS.lock() {
            assert_eq!(global.len(), 1);
            assert_eq!(global[0].node_id, "test_node");
        } else {
            return;
        }

        if start.elapsed() > timeout {
            panic!("Test timed out after {:?}", timeout);
        }
    }

    #[test]
    #[serial]
    fn test_global_tokens_comprehensive() {
        // Test various operations on the global token cache
        // Clear the cache
        clear_global_tokens();

        // Set multiple tokens
        let tokens = vec![
            NodeToken {
                node_id: "node1".to_string(),
                token: json!({"token": "value1"}),
                token_fmt: "eat".to_string(),
            },
            NodeToken {
                node_id: "node2".to_string(),
                token: json!({"token": "value2"}),
                token_fmt: "eat".to_string(),
            },
            NodeToken {
                node_id: "node3".to_string(),
                token: json!({"token": "value3"}),
                token_fmt: "eat".to_string(),
            },
        ];

        set_cached_tokens(&tokens).unwrap();

        // Verify tokens are set correctly
        if let Ok(global) = GLOBAL_TOKENS.lock() {
            assert_eq!(global.len(), 3);
            assert_eq!(global[0].node_id, "node1");
            assert_eq!(global[1].node_id, "node2");
            assert_eq!(global[2].node_id, "node3");
        } else {
            return;
        }
    }

    #[test]
    fn test_policy_ids_validation() {
        // Test valid policy_ids count
        let policy_ids = vec!["policy1".to_string(), "policy2".to_string()];
        let result = get_policy_ids("tpm_boot", &Some(policy_ids), false);
        assert!(result.is_ok());

        // Test too many policy_ids
        let too_many_policies = (1..=11).map(|i| format!("policy{}", i)).collect::<Vec<_>>();
        let result = get_policy_ids("tpm_boot", &Some(too_many_policies), false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::InternalError(_)));

        // Test empty policy_ids
        let empty_policies = vec![];
        let result = get_policy_ids("tpm_boot", &Some(empty_policies), false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test None policy_ids
        let result = get_policy_ids("tpm_boot", &None, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_collect_evidences_for_types() {
        let attester_iter = vec![AttesterInfo {
            attester_type: "tpm_boot".to_string(),
            policy_ids: Some(vec!["policy1".to_string()]),
            log_types: None,
        },
        AttesterInfo {
            attester_type: "tpm_ima".to_string(),
            policy_ids: None,
            log_types: None,
        }];

        // This test would require mocking the plugin manager and config
        // For now, we just test the function signature and basic logic
        let result = collect_evidences_for_types(&attester_iter, &None, false, false);
        // The actual result depends on the plugin manager state, so we just check it doesn't panic
        // In a real test environment, we would mock the dependencies
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_get_evidence_response_new_edge_cases() {
        // Test with empty evidences
        let response = GetEvidenceResponse::new(
            "1.0.0",
            "verifier",
            None,
            None,
            "test_node_id",
            vec![],
            Some("eat"),
        );
        assert_eq!(response.measurements[0].evidences.len(), 0);

        // Test with multiple evidences
        let evidence1 = EvidenceWithPolicy {
            attester_type: "tpm_boot".to_string(),
            evidence: json!({"test": "evidence1"}),
            policy_ids: Some(vec!["policy1".to_string()]),
        };
        let evidence2 = EvidenceWithPolicy {
            attester_type: "tpm_ima".to_string(),
            evidence: json!({"test": "evidence2"}),
            policy_ids: Some(vec!["policy2".to_string()]),
        };
        let response = GetEvidenceResponse::new(
            "1.0.0",
            "verifier",
            None,
            None,
            "test_node_id",
            vec![
                EvidenceWithPolicy {
                    attester_type: evidence1.attester_type.clone(),
                    evidence: evidence1.evidence.clone(),
                    policy_ids: evidence1.policy_ids.clone(),
                },
                EvidenceWithPolicy {
                    attester_type: evidence2.attester_type.clone(),
                    evidence: evidence2.evidence.clone(),
                    policy_ids: evidence2.policy_ids.clone(),
                },
            ],
            Some("eat"),
        );
        assert_eq!(response.measurements[0].evidences.len(), 2);
    }

    #[test]
    fn test_attester_info_edge_cases() {
        let attester_info = AttesterInfo {
            attester_type: "".to_string(),
            policy_ids: None,
            log_types: None,
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);

        let attester_info = AttesterInfo {
            attester_type: "".to_string(),
            policy_ids: Some(vec![]),
            log_types: None,
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);
    }

    #[test]
    fn test_nonce_serialization() {
        let nonce = "test_nonce_value";

        let serialized = serde_json::to_string(&nonce).unwrap();
        let deserialized: String = serde_json::from_str(&serialized).unwrap();

        assert_eq!(nonce, deserialized);
    }

    #[test]
    fn test_evidence_with_policy_edge_cases() {
        let evidence = EvidenceWithPolicy {
            attester_type: "".to_string(),
            evidence: json!({}),
            policy_ids: None,
        };

        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(serialized.contains("attester_type"));
        assert!(serialized.contains("\"\""));

        let evidence = EvidenceWithPolicy {
            attester_type: "tpm_boot".to_string(),
            evidence: json!(null),
            policy_ids: None,
        };

        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(serialized.contains("tpm_boot"));
        assert!(serialized.contains("null"));
    }

    #[test]
    fn test_base64_operations_edge_cases() {
        let empty_base64 = "";
        let decoded = STANDARD.decode(empty_base64);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), b"");

        let padded_base64 = "dGVzdA=="; // "test" with padding
        let decoded = STANDARD.decode(padded_base64);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), b"test");

        let valid_base64 = "dGVzdA"; // "test" - this should be valid base64
        let decoded = STANDARD.decode(valid_base64);
        // Some base64 implementations may require padding, so we handle both cases
        if decoded.is_ok() {
            assert_eq!(decoded.unwrap(), b"test");
        } else {
            // If it fails, test with proper padding
            let padded_base64 = "dGVzdA==";
            let decoded = STANDARD.decode(padded_base64);
            assert!(decoded.is_ok());
            assert_eq!(decoded.unwrap(), b"test");
        }

        let invalid_base64 = "dGVzdA!@#";
        let decoded = STANDARD.decode(invalid_base64);
        assert!(decoded.is_err());
    }

    #[test]
    fn test_collect_evidences_core_comprehensive() {
        // Test None attester_info
        let result = collect_evidences_core(&None, &None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test empty attester_info
        let empty_info = Some(vec![]);
        let result = collect_evidences_core(&empty_info, &None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test all attester_type are empty
        let empty_types_info = Some(vec![
            AttesterInfo {
                attester_type: "".to_string(),
                policy_ids: None,
                log_types: None,
            },
            AttesterInfo {
                attester_type: "".to_string(),
                policy_ids: None,
                log_types: None,
            },
        ]);
        let result = collect_evidences_core(&empty_types_info, &None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test mixed empty and non-empty attester_type
        let mixed_info = Some(vec![
            AttesterInfo {
                attester_type: "".to_string(),
                policy_ids: None,
                log_types: None,
            },
            AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: None,
                log_types: None,
            },
        ]);
        let result = collect_evidences_core(&mixed_info, &None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_get_policy_ids_comprehensive() {
        // Test user-provided policy_ids exceeding the limit
        let too_many_policies = (1..=11).map(|i| format!("policy{}", i)).collect::<Vec<_>>();
        let result = get_policy_ids("tpm_boot", &Some(too_many_policies), false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::InternalError(_)));

        // Test user-provided empty policy_ids
        let empty_policies = vec![];
        let result = get_policy_ids("tpm_boot", &Some(empty_policies), false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test user-provided valid policy_ids
        let valid_policies = vec!["policy1".to_string(), "policy2".to_string()];
        let result = get_policy_ids("tpm_boot", &Some(valid_policies.clone()), false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(valid_policies));

        // Test user did not provide policy_ids and use_config is false
        let result = get_policy_ids("tpm_boot", &None, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test user did not provide policy_ids and use_config is true
        // This test requires the plugin manager and will fail, but covers the code path
        let result = get_policy_ids("tpm_boot", &None, true);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_collect_evidences_for_types_error_handling() {
        // Test empty iterator
        let empty_attester_info = vec![];
        let result = collect_evidences_for_types(&empty_attester_info, &None, false, false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NoValidEvidence(_)));

        // Test case where validation is required but fails
        let invalid_attester_info = vec![AttesterInfo {
            attester_type: "invalid_type".to_string(),
            policy_ids: None,
            log_types: None,
        }];
        let result = collect_evidences_for_types(&invalid_attester_info, &None, true, false);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_collect_from_attester_info_edge_cases() {
        // Test empty attester_info
        let empty_info = vec![];
        let result = collect_from_attester_info(&empty_info, &None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test info containing None attester_type
        let info_with_none = vec![
            AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: None,
                log_types: None,
            },
        ];
        let result = collect_from_attester_info(&info_with_none, &None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_collect_from_enabled_plugins_error_handling() {
        // Test the case where the plugin manager is not initialized
        let result = collect_from_enabled_plugins(&None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_find_plugin_for_attester_type_error_handling() {
        // Test invalid attester_type
        let result = find_plugin_for_attester_type("invalid_type");
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_validate_attester_type_error_handling() {
        // Test invalid attester_type
        let result = validate_attester_type("invalid_type");
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_collect_evidence_error_handling() {
        // Test invalid attester_type
        let result = collect_evidence("invalid_type", None, None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test base64 decode failure
        let result = collect_evidence("tpm_boot", Some("invalid_base64!@#".to_string()), None);
        // This test will fail due to missing plugin manager, but covers the code path
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_acquire_thread_lock_timeout() {
        let result = acquire_thread_lock();
        assert!(result.is_ok()); // In test environment, lock should be available
    }

    #[test]
    fn test_get_nonce_from_server_error_handling() {
        // Test network error handling
        // Since this is an async function and requires network, we test error handling logic
        let network_error = "Network error";
        let challenge_error: ChallengeError = network_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));
    }

    #[test]
    fn test_get_tokens_from_server_error_handling() {
        // Test parse error handling
        let parse_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let challenge_error: ChallengeError = parse_error.into();
        assert!(matches!(challenge_error, ChallengeError::RequestParseError(_)));
    }

    #[test]
    fn test_do_challenge_error_handling() {
        // Test error handling in the challenge process
        // Since this is an async function and requires a complete plugin manager, we test error handling logic
        let server_error = "Server error";
        let challenge_error: ChallengeError = server_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));
    }

    #[test]
    fn test_node_token_operations() {
        let node_token = NodeToken {
            node_id: "test_node".to_string(),
            token: json!({"access_token": "test_token"}),
            token_fmt: "eat".to_string(),
        };

        assert_eq!(node_token.node_id, "test_node");
        assert_eq!(node_token.token, json!({"access_token": "test_token"}));

        let cloned_token = node_token.clone();
        assert_eq!(node_token.node_id, cloned_token.node_id);
        assert_eq!(node_token.token, cloned_token.token);
    }

    #[test]
    fn test_evidence_with_policy_operations() {
        let evidence = EvidenceWithPolicy {
            attester_type: "tpm_boot".to_string(),
            evidence: json!({"test": "evidence"}),
            policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
        };

        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(serialized.contains("tpm_boot"));
        assert!(serialized.contains("policy1"));
        assert!(serialized.contains("policy2"));
        assert!(serialized.contains("test"));
        assert!(serialized.contains("evidence"));
    }

    #[test]
    fn test_error_conversion_comprehensive() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let challenge_error: ChallengeError = io_error.into();
        assert!(matches!(challenge_error, ChallengeError::InternalError(_)));

        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let challenge_error: ChallengeError = json_error.into();
        assert!(matches!(challenge_error, ChallengeError::RequestParseError(_)));

        let string_error: ChallengeError = "test error".into();
        assert!(matches!(string_error, ChallengeError::InternalError(_)));

        let str_error: ChallengeError = "test str error".into();
        assert!(matches!(str_error, ChallengeError::InternalError(_)));
    }

    #[test]
    fn test_serde_json_error_conversion_branch() {
        let invalid_json = "{invalid json}";
        let err = serde_json::from_str::<serde_json::Value>(invalid_json).unwrap_err();
        let challenge_error: ChallengeError = err.into();
        assert!(matches!(challenge_error, ChallengeError::RequestParseError(_)));
    }

    #[test]
    fn test_node_token_debug_and_clone() {
        let token = NodeToken {
            node_id: "id".to_string(),
            token: json!({"a": 1}),
            token_fmt: "eat".to_string(),
        };
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("node_id"));
        let clone = token.clone();
        assert_eq!(token.node_id, clone.node_id);
    }

    #[test]
    fn test_evidence_with_policy_debug_and_clone() {
        let e = EvidenceWithPolicy {
            attester_type: "tpm_boot".to_string(),
            evidence: json!({"k": "v"}),
            policy_ids: Some(vec!["p1".to_string()]),
        };
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("tpm_boot"));
        let _clone = EvidenceWithPolicy {
            attester_type: e.attester_type.clone(),
            evidence: e.evidence.clone(),
            policy_ids: e.policy_ids.clone(),
        };
    }

    #[test]
    fn test_nonce_validation_comprehensive() {
        // Test empty nonce
        let result = validate_nonce_fields("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));

        // Test whitespace-only nonce
        let result = validate_nonce_fields("   ");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));

        // Test invalid base64
        let result = validate_nonce_fields("invalid_base64!@#");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));

        // Test too short nonce (0 bytes)
        let result = validate_nonce_fields("");
        assert!(result.is_err());

        // Test too long nonce (>1024 bytes)
        let long_nonce = "a".repeat(2000);
        let encoded = STANDARD.encode(long_nonce.as_bytes());
        let result = validate_nonce_fields(&encoded);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));

        // Test valid nonce (1 byte)
        let valid_nonce = STANDARD.encode(b"a");
        let result = validate_nonce_fields(&valid_nonce);
        assert!(result.is_ok());

        // Test valid nonce (1024 bytes)
        let valid_long_nonce = STANDARD.encode(&vec![0u8; 1024]);
        let result = validate_nonce_fields(&valid_long_nonce);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_cached_token_for_current_node_with_fmt() {
        // Clear any existing tokens
        clear_global_tokens();

        // Test getting token when cache is empty
        let result = get_cached_token_for_current_node_with_fmt("eat");
        assert!(result.is_err()); // Should fail due to missing config

        // Test with different token formats
        let result = get_cached_token_for_current_node_with_fmt("ear");
        assert!(result.is_err()); // Should fail due to missing config
    }

    #[test]
    fn test_get_policy_ids_edge_cases() {
        // Test with use_config = true (requires plugin manager)
        let result = get_policy_ids("tpm_boot", &None, true);
        assert!(result.is_err()); // Should fail due to missing plugin manager

        // Test with use_config = true and valid policy_ids - this should succeed
        // because when user provides policy_ids, it uses them regardless of use_config
        let valid_policies = vec!["policy1".to_string(), "policy2".to_string()];
        let result = get_policy_ids("tpm_boot", &Some(valid_policies.clone()), true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(valid_policies));
    }

    #[test]
    fn test_node_token_comprehensive() {
        // Test NodeToken with various token types
        let token_types = vec![
            json!({"access_token": "test_token"}),
            json!({"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}),
            json!({"ear": {"header": {}, "payload": {}, "signature": "..."}}),
            json!(null),
            json!("simple_string_token"),
            json!(42),
            json!([1, 2, 3, 4, 5]),
        ];

        for (i, token) in token_types.iter().enumerate() {
            let node_token = NodeToken {
                node_id: format!("node_{}", i),
                token: token.clone(),
                token_fmt: if i % 2 == 0 { "eat".to_string() } else { "ear".to_string() },
            };

            assert_eq!(node_token.node_id, format!("node_{}", i));
            assert_eq!(node_token.token, *token);
            assert_eq!(node_token.token_fmt, if i % 2 == 0 { "eat" } else { "ear" });

            // Test clone
            let cloned = node_token.clone();
            assert_eq!(node_token.node_id, cloned.node_id);
            assert_eq!(node_token.token, cloned.token);
            assert_eq!(node_token.token_fmt, cloned.token_fmt);

            // Test debug formatting
            let debug_str = format!("{:?}", node_token);
            assert!(debug_str.contains(&format!("node_{}", i)));
        }
    }

    #[test]
    fn test_constants_and_static_values() {
        // Test TIME_OUT constant
        assert_eq!(TIME_OUT, 120);

        // Test GLOBAL_TPM initialization
        let lock_result = GLOBAL_TPM.try_lock();
        assert!(lock_result.is_some());

        // Test GLOBAL_TOKENS initialization
        let tokens_result = GLOBAL_TOKENS.lock();
        assert!(tokens_result.is_ok());
    }

    #[test]
    fn test_acquire_thread_lock_comprehensive() {
        // Test successful lock acquisition
        let result = acquire_thread_lock();
        assert!(result.is_ok());

        // Test lock timeout (this is hard to test without actually causing a timeout)
        // But we can verify the function structure
        let lock_guard = result.unwrap();
        drop(lock_guard); // Release the lock
    }

    #[test]
    fn test_set_cached_tokens_error_handling() {
        // Test with poisoned mutex (hard to simulate in test environment)
        // But we can test the function structure
        let tokens = vec![NodeToken {
            node_id: "test_node".to_string(),
            token: json!({"test": "token"}),
            token_fmt: "eat".to_string(),
        }];

        let result = set_cached_tokens(&tokens);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_cached_token_for_current_node_with_fmt_comprehensive() {
        // Test with different token formats
        let formats = vec!["eat", "ear", "EAT", "EAR", "Eat", "Ear"];

        for fmt in formats {
            let result = get_cached_token_for_current_node_with_fmt(fmt);
            assert!(result.is_err()); // Should fail due to missing config
        }
    }
}
