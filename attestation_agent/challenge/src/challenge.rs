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

use crate::challenge_error::ChallengeError;
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

const TIME_OUT: u64 = 120;

#[derive(Debug, Clone)]
pub struct NodeToken {
    node_id: String,
    token: Value,
}

static GLOBAL_TPM: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Global cached tokens for reuse between requests (sync Mutex)
pub static GLOBAL_TOKENS: Lazy<StdMutex<Vec<NodeToken>>> = Lazy::new(|| StdMutex::new(Vec::new()));

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
/// Information about an attester, including type and policy IDs
pub struct AttesterInfo {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Nonce structure used for challenge/attestation
pub struct Nonce {
    pub iat: u64,
    pub value: String,
    pub signature: String,
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
    pub nonce: Option<Nonce>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<serde_json::Value>,
    pub evidences: Vec<EvidenceWithPolicy>,
}

#[derive(Debug, Serialize)]
/// Response structure for evidence collection
pub struct GetEvidenceResponse {
    pub agent_version: String,
    pub nonce_type: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_nonce: Option<String>,
    pub measurements: Vec<Measurement>,
}

impl GetEvidenceResponse {
    pub fn new(
        agent_version: &str,
        nonce_type: &str,
        user_nonce: Option<&String>,
        nonce: Option<&Nonce>,
        attester_data: Option<&serde_json::Value>,
        node_id: &str,
        evidences: Vec<EvidenceWithPolicy>,
    ) -> Self {
        GetEvidenceResponse {
            agent_version: agent_version.to_string(),
            nonce_type: nonce_type.to_string(),
            user_nonce: if nonce_type == "user" { user_nonce.cloned() } else { None },
            measurements: vec![Measurement {
                node_id: node_id.to_string(),
                nonce: nonce.cloned(),
                attester_data: attester_data.cloned(),
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
pub fn set_cached_tokens(tokens: &[NodeToken]) {
    let mut global = GLOBAL_TOKENS.lock().unwrap();
    *global = tokens.to_vec();
}

/// Get the cached token for current `node_id` as `serde_json::Value` (sync)
pub fn get_cached_token_for_current_node() -> Option<Value> {
    let node_id = get_node_id().ok()?;
    let global = GLOBAL_TOKENS.lock().unwrap();
    global.iter().find(|nt| nt.node_id == node_id).map(|nt| nt.token.clone())
}

/// Get the node ID (UUID) from configuration
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
        return Err(ChallengeError::NoEnabledPlugins);
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
                };
                enabled_attester_types.push(attester_type.to_string());
            }
        }
    }

    if enabled_attester_types.is_empty() {
        log::error!("No enabled attester types found in config");
        return Err(ChallengeError::NoEnabledPlugins);
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
                        (config::PluginParams::TpmBoot(_), "tpm_boot") | (config::PluginParams::TpmIma(_), "tpm_ima")
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
fn collect_evidence(attester_type: &str, nonce_value: Option<String>) -> Result<serde_json::Value, ChallengeError> {
    let (plugin, _) = find_plugin_for_attester_type(attester_type)?;
    let node_id = get_node_id()?;
    let nonce_bytes = nonce_value.as_ref().map(|s| {
        STANDARD.decode(s).map_err(|e| {
            log::error!("Failed to decode base64 nonce: {}", e);
            ChallengeError::NonceInvalid(format!("Failed to decode base64 nonce: {}", e))
        })
    }).transpose()?;

    let _lock_guard = acquire_thread_lock()?;
    match plugin.collect_evidence(Some(&node_id), nonce_bytes.as_deref()) {
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
fn collect_evidences_for_types<I>(
    attester_iter: I,
    nonce_value: &Option<String>,
    need_validate: bool,
    use_config: bool,
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError>
where
    I: IntoIterator<Item = (String, Option<Vec<String>>)>,
{
    let mut all_evidences = Vec::new();
    for (attester_type, policy_ids_hint) in attester_iter {
        if need_validate {
            validate_attester_type(&attester_type)?;
        }

        let evidence_value = collect_evidence(&attester_type, nonce_value.clone()).map_err(|e| {
            log::error!("Failed to collect evidence for '{}': {}", attester_type, e);
            ChallengeError::EvidenceCollectionFailed(format!(
                "Failed to collect evidence for '{}': {}",
                attester_type, e
            ))
        })?;

        let policy_ids = get_policy_ids(&attester_type, &policy_ids_hint, use_config)?;
        all_evidences.push(EvidenceWithPolicy { attester_type, evidence: evidence_value, policy_ids });
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
    let attester_iter = info.iter().filter_map(|a| a.attester_type.as_ref().map(|t| (t.clone(), a.policy_ids.clone())));
    // For collect_from_attester_info, use_config is false
    collect_evidences_for_types(attester_iter, nonce_value, true, false)
}

/// Collect evidence from all enabled plugins
fn collect_from_enabled_plugins(nonce_value: &Option<String>) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    let enabled_types = get_enabled_attester_types()?;
    let attester_iter = enabled_types.into_iter().map(|t| (t, None));
    // For collect_from_enabled_plugins, use_config is true
    collect_evidences_for_types(attester_iter, nonce_value, false, true)
}

/// Core function to collect evidences from attester info or enabled plugins
pub fn collect_evidences_core(
    attester_info: &Option<Vec<AttesterInfo>>,
    nonce_value: &Option<String>,
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    match attester_info {
        Some(info) if !info.is_empty() => {
            let all_types_empty = info.iter().all(|attester| {
                attester.attester_type.is_none() || attester.attester_type.as_ref().unwrap().is_empty()
            });

            if all_types_empty {
                log::info!("All attester_types empty, collecting from enabled plugins");
                // Case 1: All attester_types are empty
                // Get all enabled plugin types using policy_ids from config
                collect_from_enabled_plugins(nonce_value)
            } else {
                log::info!("Collecting from provided attester_info");
                // Case 2: Use information from attester_info
                collect_from_attester_info(info, nonce_value)
            }
        },
        // Default case: Get all enabled plugin types
        _ => {
            log::info!("No attester_info provided, collecting from enabled plugins");
            collect_from_enabled_plugins(nonce_value)
        },
    }
}

/// Validate Nonce fields, return `ChallengeError` if invalid
pub fn validate_nonce_fields(nonce: &Nonce) -> Result<(), ChallengeError> {
    if nonce.value.trim().is_empty() || nonce.signature.trim().is_empty() || nonce.iat == 0 {
        return Err(ChallengeError::NonceInvalid("One or more nonce fields are empty".to_string()));
    }
    let value_len = nonce.value.len();
    if !(64..=1024).contains(&value_len) {
        return Err(ChallengeError::NonceInvalid(format!(
            "nonce.value length must be between 64 and 1024 bytes, got {} bytes",
            value_len
        )));
    }
    let sig_len = nonce.signature.len();
    if sig_len < 64 {
        return Err(ChallengeError::NonceInvalid(format!(
            "nonce.signature length must be at least 64 bytes, got {} bytes",
            sig_len
        )));
    }
    Ok(())
}

/// Request a nonce from the server for attestation
async fn get_nonce_from_server(
    agent_version: &str,
    attester_info: &Option<Vec<AttesterInfo>>,
) -> Result<Nonce, ChallengeError> {
    let attester_types = match attester_info {
        Some(info) if !info.is_empty() => {
            let filtered: Vec<_> =
                info.iter().filter_map(|a| a.attester_type.clone()).filter(|s| !s.trim().is_empty()).collect();
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

    let nonce: Nonce = if let Some(nonce_val) = json_value.get("nonce") {
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
        node_tokens.push(NodeToken { node_id, token: token_val });
    }

    Ok(node_tokens)
}

/// Main entry for the attestation challenge process
pub async fn do_challenge(
    attester_info: &Option<Vec<AttesterInfo>>,
    attester_data: &Option<serde_json::Value>,
) -> Result<serde_json::Value, ChallengeError> {
    log::info!("Starting challenge request.");

    let nonce = get_nonce_from_server(env!("CARGO_PKG_VERSION"), attester_info).await?;

    let evidences = match collect_evidences_core(attester_info, &Some(nonce.value.clone())) {
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
        "default",
        None,
        Some(&nonce),
        attester_data.as_ref(),
        &node_id,
        evidences,
    );

    let node_tokens = get_tokens_from_server(&evidence_response).await?;
    set_cached_tokens(&node_tokens);

    for nt in node_tokens {
        if nt.node_id == node_id {
            log::info!("Successfully obtained token for node_id {}", node_id);
            return Ok(nt.token);
        }
    }

    log::error!("Token for node_id {} not found in server response", node_id);
    Err(ChallengeError::TokenNotReceived)
}
