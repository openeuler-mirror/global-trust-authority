use serde::{Deserialize, Serialize};
use crate::challenge_error::ChallengeError;
use std::sync::Mutex;
use lazy_static::lazy_static;
use log;
use config::{AGENT_CONFIG, PluginConfig};
use plugin_manager::{PluginManagerInstance, AgentPlugin, AgentHostFunctions, PluginManager};
use std::sync::Arc;
use std::time::{Duration, Instant};
use reqwest::Method;
use agent_utils::Client;

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct NodeToken {
    node_id: String,
    token: Value,
}

// Global cached tokens for reuse between requests
lazy_static! {
    static ref GLOBAL_TOKENS: Mutex<Vec<NodeToken>> = Mutex::new(Vec::new());
}

// Global mutex for synchronizing TPM access
lazy_static! {
    static ref TPM_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
/// Information about an attester, including type and policy IDs
pub struct AttesterInfo {
    pub attester_type: Option<String>,
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
    pub policy_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
/// Measurement structure containing node and evidence info
pub struct Measurement {
    pub node_id: String,
    pub nonce: Option<Nonce>,
    pub attester_data: Option<String>,
    pub evidences: Vec<EvidenceWithPolicy>,
}

#[derive(Debug, Serialize)]
/// Response structure for evidence collection
pub struct GetEvidenceResponse {
    pub agent_version: String,
    pub nonce_type: String,
    pub user_nonce: Option<String>,
    pub measurements: Vec<Measurement>,
}

impl GetEvidenceResponse {
    pub fn new(
        agent_version: &str,
        nonce_type: &str,
        user_nonce: Option<&String>,
        nonce: Option<&Nonce>,
        attester_data: Option<&String>,
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

/// Set the global cached tokens
pub fn set_cached_tokens(tokens: Vec<NodeToken>) {
    let mut global = GLOBAL_TOKENS.lock().unwrap();
    *global = tokens;
}

/// Get the cached token for current node_id as serde_json::Value
pub fn get_cached_token() -> Option<serde_json::Value> {
    let node_id = match get_node_id() {
        Ok(id) => id,
        Err(_) => return None,
    };
    let global = GLOBAL_TOKENS.lock().unwrap();
    for nt in global.iter() {
        if nt.node_id == node_id {
            return Some(nt.token.clone());
        }
    }
    None
}

/// Try to acquire the TPM lock with timeout, to synchronize TPM access
pub fn acquire_tpm_lock() -> Result<std::sync::MutexGuard<'static, ()>, ChallengeError> {
    let start = Instant::now();
    let timeout_duration = Duration::from_secs(120);

    while start.elapsed() < timeout_duration {
        // Try to acquire the lock
        if let Ok(guard) = TPM_LOCK.try_lock() {
            log::info!("Acquire tpm lock success.");
            return Ok(guard);
        }
        // Sleep briefly to avoid busy waiting
        std::thread::sleep(Duration::from_millis(10));
    }
    
    Err(ChallengeError::InternalError(
        "Timeout while waiting for TPM lock".to_string()
    ))
}

/// Get the node ID (UUID) from configuration
pub fn get_node_id() -> Result<String, ChallengeError> {
    let config = AGENT_CONFIG.get_instance()
        .map_err(|e| ChallengeError::ConfigError(e.to_string()))?;
    
    config.agent.uuid
        .clone()
        .ok_or_else(|| ChallengeError::ConfigError("Agent UUID not configured".to_string()))
}

/// Get all enabled attester types from the plugin manager and config
fn get_enabled_attester_types() -> Result<Vec<String>, ChallengeError> {
    let plugin_manager = PluginManager::<dyn AgentPlugin, AgentHostFunctions>::get_instance();
    
    if !plugin_manager.is_initialized() {
        return Err(ChallengeError::InternalError("Plugin manager not initialized".to_string()));
    }

    let enabled_plugins = plugin_manager.get_plugin_types();
    if enabled_plugins.is_empty() {
        return Err(ChallengeError::NoEnabledPlugins);
    }

    let config = AGENT_CONFIG.get_instance()
        .map_err(|e| ChallengeError::ConfigError(e.to_string()))?;

    let mut enabled_attester_types = Vec::new();
    
    for plugin_name in &enabled_plugins {
        if let Some(plugin_config) = config.plugins.iter().find(|p| &p.name == plugin_name) {
            if let Some(params) = &plugin_config.params {
                let attester_type = match params {
                    config::PluginParams::TpmBoot(_) => "tpm_boot",
                    config::PluginParams::TpmIma(_) => "tpm_ima",
                    config::PluginParams::TpmDim(_) => "tpm_dim",
                };
                enabled_attester_types.push(attester_type.to_string());
            }
        }
    }

    if enabled_attester_types.is_empty() {
        return Err(ChallengeError::NoEnabledPlugins);
    }

    Ok(enabled_attester_types)
}

/// Find the plugin and config that matches the given attester_type
fn find_plugin_for_attester_type(
    attester_type: &str
) -> Result<(Arc<dyn AgentPlugin>, PluginConfig), ChallengeError> {
    let config = AGENT_CONFIG.get_instance()
        .map_err(|e| ChallengeError::ConfigError(e.to_string()))?;
    let plugin_config = config.plugins.iter()
        .find(|p| p.enabled && p.params.as_ref().map_or(false, |params| {
            match (params, attester_type) {
                (config::PluginParams::TpmBoot(_), "tpm_boot") => true,
                (config::PluginParams::TpmIma(_), "tpm_ima") => true,
                (config::PluginParams::TpmDim(_), "tpm_dim") => true,
                _ => false
            }
        }))
        .ok_or_else(|| ChallengeError::PluginNotFound(attester_type.to_string()))?
        .clone();

    let plugin_manager = PluginManager::<dyn AgentPlugin, AgentHostFunctions>::get_instance();
    if !plugin_manager.is_initialized() {
        return Err(ChallengeError::InternalError("Plugin manager not initialized".to_string()));
    }
    let plugin = plugin_manager.get_plugin(&plugin_config.name)
        .ok_or_else(|| ChallengeError::PluginNotFound(plugin_config.name.clone()))?;

    Ok((plugin, plugin_config))
}

/// Validate if the attester_type exists and is enabled
fn validate_attester_type(attester_type: &str) -> Result<bool, ChallengeError> {
    // Attempt to fetch the plugin; success confirms it exists and is enabled.
    find_plugin_for_attester_type(attester_type)?;
    Ok(true)
}

/// Collect evidence for a specific attester type and nonce
fn collect_evidence(
    attester_type: &str,
    nonce_value: Option<String>,
) -> Result<serde_json::Value, ChallengeError> {
    let (plugin, _) = find_plugin_for_attester_type(attester_type)?;

    let node_id = get_node_id()?;
    let nonce_bytes = nonce_value.as_ref().map(|s| s.as_bytes());

    match plugin.collect_evidence(Some(&node_id), nonce_bytes) {
        Ok(evidence_value) => Ok(evidence_value),
        Err(e) => Err(ChallengeError::EvidenceCollectionFailed(e.to_string()))
    }
}

fn get_policy_ids(
    attester_type: &str,
    input_policy_ids: &Option<Vec<String>>
) -> Result<Option<Vec<String>>, ChallengeError> {
    if let Some(ids) = input_policy_ids {
        if ids.len() > 10 {
            return Err(ChallengeError::InternalError(format!(
                "Too many policy_ids for attester_type '{}', max allowed is 10", attester_type
            )));
        }
        if !ids.is_empty() {
            return Ok(Some(ids.clone()));
        }
    }

    let (_, plugin_config) = find_plugin_for_attester_type(attester_type)?;
    if plugin_config.policy_id.len() > 10 {
        return Err(ChallengeError::InternalError(format!(
            "Too many policy_ids in config for attester_type '{}', max allowed is 10", attester_type
        )));
    }
    Ok(if plugin_config.policy_id.is_empty() {
        None
    } else {
        Some(plugin_config.policy_id)
    })
}

/// Generic evidence collection helper function
fn collect_evidences_for_types<I>(
    attester_iter: I,
    nonce_value: &Option<String>,
    need_validate: bool,
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError>
where
    I: IntoIterator<Item = (String, Option<Vec<String>>)> {
    let mut all_evidences = Vec::new();
    for (attester_type, policy_ids_hint) in attester_iter {
        if need_validate {
            validate_attester_type(&attester_type)?;
        }

        let evidence_value = collect_evidence(&attester_type, nonce_value.clone())
            .map_err(|e| ChallengeError::EvidenceCollectionFailed(
                format!("Failed to collect evidence for '{}': {}", attester_type, e)
            ))?;

        let policy_ids = get_policy_ids(&attester_type, &policy_ids_hint)?;
        all_evidences.push(EvidenceWithPolicy {
            attester_type,
            evidence: evidence_value,
            policy_ids,
        });
    }
    if all_evidences.is_empty() {
        return Err(ChallengeError::NoValidEvidence("No evidence collected".to_string()));
    }
    Ok(all_evidences)
}

/// Collect evidence from provided attester info list
fn collect_from_attester_info(
    info: &[AttesterInfo],
    nonce_value: &Option<String>
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    let attester_iter = info.iter().filter_map(|a| {
        a.attester_type.as_ref().map(|t| (t.clone(), a.policy_ids.clone()))
    });
    collect_evidences_for_types(attester_iter, nonce_value, true)
}

/// Collect evidence from all enabled plugins
fn collect_from_enabled_plugins(
    nonce_value: &Option<String>
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    let enabled_types = get_enabled_attester_types()?;
    let attester_iter = enabled_types.into_iter().map(|t| (t, None));
    collect_evidences_for_types(attester_iter, nonce_value, false)
}

/// Core function to collect evidences from attester info or enabled plugins
pub fn collect_evidences_core(
    attester_info: &Option<Vec<AttesterInfo>>,
    nonce_value: &Option<String>,
) -> Result<Vec<EvidenceWithPolicy>, ChallengeError> {
    match attester_info {
        Some(info) if !info.is_empty() => {
            let all_types_empty = info.iter()
                .all(|attester| attester.attester_type.is_none() || attester.attester_type.as_ref().unwrap().is_empty());
            
            if all_types_empty {
                // Case 1: All attester_types are empty
                // Get all enabled plugin types using policy_ids from config
                collect_from_enabled_plugins(nonce_value)
            } else {
                // Case 2: Use information from attester_info
                collect_from_attester_info(info, nonce_value)
            }
        },
        // Default case: Get all enabled plugin types
        _ => collect_from_enabled_plugins(nonce_value)
    }
}

/// Validate Nonce fields, return ChallengeError if invalid
pub fn validate_nonce_fields(nonce: &Nonce) -> Result<(), ChallengeError> {
    if nonce.value.trim().is_empty() ||
       nonce.signature.trim().is_empty() ||
       nonce.iat == 0 {
        return Err(ChallengeError::NonceInvalid("One or more nonce fields are empty".to_string()));
    }
    let value_len = nonce.value.as_bytes().len();
    if value_len < 64 || value_len > 1024 {
        return Err(ChallengeError::NonceInvalid(format!(
            "nonce.value length must be between 64 and 1024 bytes, got {} bytes",
            value_len
        )));
    }
    let sig_len = nonce.signature.as_bytes().len();
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
            info.iter()
                .filter_map(|a| a.attester_type.clone())
                .collect::<Vec<_>>()
        },
        _ => get_enabled_attester_types()?,
    };

    let request = serde_json::json!({
        "agent_version": agent_version,
        "attester_type": attester_types
    });

    // Mock response matching the required format
    let json_value = serde_json::json!({
        "service_version": "1.0.0",
        "nonces": {
            "iat": 1713412345,
            "value": "5J7Q3sQbF6Yp6R6T1Qm8k1gX7j9YzvH4l6eQ2J1s8x0a9vT3h2K5z8W0u4x9V7n2b1c6e3w0p8m7u5q9t4r3y2z0v1s6d8a5g",
            "signature": "Y0t2bGxwR1F6dGJmU1l4N3lBUXk2T2JZc3h5T0l6Z3Z4d2lQd2F6R0ZyZ3l6Z2V4V2V5d2F0Y3l6a2N6d2p6d2x5d2V6d2s="
        }
    });

    // let client = Client::instance();
    // let response = client
    //     .request(Method::POST, "/challenge", Some(request))
    //     .await
    //     .map_err(|e| ChallengeError::NetworkError(format!("Failed to get nonce: {}", e)))?;

    // let json_value = response
    //     .json::<serde_json::Value>()
    //     .await
    //     .map_err(|e| ChallengeError::RequestParseError(format!("Failed to parse nonce response: {}", e)))?;

    if let Some(msg) = json_value.get("message").and_then(|v| v.as_str()) {
        if !msg.is_empty() {
            return Err(ChallengeError::ServerError(msg.to_string()));
        }
    }

    let nonce: Nonce = match json_value.get("nonces") {
        Some(nonce_val) => serde_json::from_value(nonce_val.clone())
            .map_err(|e| ChallengeError::RequestParseError(format!("Failed to parse nonce: {}", e)))?,
        None => return Err(ChallengeError::NonceNotProvided),
    };
    validate_nonce_fields(&nonce)?;

    Ok(nonce)
}

/// Send the evidence to the attestation server and extract all node tokens from the response.
async fn get_tokens_from_server(
    evidence: &GetEvidenceResponse
) -> Result<Vec<NodeToken>, ChallengeError> {
    // Mock response matching the required format
    let long_token = concat!(
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6ImprdSIsImtpZCI6ImtpZCJ9.",
    "eyJpbnR1c2UiOiJHZW5lcmljIiwic3RhdHVzIjoiZmFpbCIsInVlaWQiOiJUUE0gQUsiL",
    "CJ0cG1fYm9vdCI6eyJhdHRlc3RhdGlvbl9zdGF0dXMiOiJmYWlsIiwicG9saWN5X2luZm",
    "8iOlt7ImFwcHJhaXNhbF9wb2xpY3lfaWQiOiJmZWM3OTA5Zi0yOGY5LTRiMjktYmU2NS0",
    "yOThlNGZjNDNmYjgiLCJwb2xpY3lfdmVyc2lvbiI6MSwiYXR0ZXN0YXRpb25fdmFsaWQi",
    "OmZhbHNlLCJjdXN0b21fZGF0YSI6eyJoYXNoX2FsZyI6InNoYTI1NiJ9fV0sImlzX2xvZ",
    "192YWxpZCI6dHJ1ZSwicGNycyI6eyJoYXNoX2FsZyI6InNoYTI1NiIsInBjcl92YWx1ZX",
    "MiOlt7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6MCwicGNyX3ZhbHVlIjoiOWQ",
    "3NTA0YmIwZDMyZjYyZDQzMzEwZjM4ZGYzN2NkZDVlNDJiZGI4M2RkMGMwNTkyZmQ5YjFj",
    "M2IxNjc3MGMzNSIsInJlcGxheV92YWx1ZSI6IjlkNzUwNGJiMGQzMmY2MmQ0MzMxMGYzO",
    "GRmMzdjZGQ1ZTQyYmRiODNkZDBjMDU5MmZkOWIxYzNiMTY3NzBjMzUifSx7ImlzX21hdG",
    "NoZWQiOnRydWUsInBjcl9pbmRleCI6MSwicGNyX3ZhbHVlIjoiMzg4NDYyNzFlMmE4NmQ",
    "2YmY0M2VmMzg4YmUyZDFjYjgzYTg5ZjFjMGJiMTU0ZmU0OTRhMWRkYTE5OGRhMjliZSIs",
    "InJlcGxheV92YWx1ZSI6IjM4ODQ2MjcxZTJhODZkNmJmNDNlZjM4OGJlMmQxY2I4M2E4O",
    "WYxYzBiYjE1NGZlNDk0YTFkZGExOThkYTI5YmUifSx7ImlzX21hdGNoZWQiOnRydWUsIn",
    "Bjcl9pbmRleCI6MiwicGNyX3ZhbHVlIjoiM2Q0NThjZmU1NWNjMDNlYTFmNDQzZjE1NjJ",
    "iZWVjOGRmNTFjNzVlMTRhOWZjZjlhNzIzNGExM2YxOThlNzk2OSIsInJlcGxheV92YWx1",
    "ZSI6IjNkNDU4Y2ZlNTVjYzAzZWExZjQ0M2YxNTYyYmVlYzhkZjUxYzc1ZTE0YTlmY2Y5Y",
    "TcyMzRhMTNmMTk4ZTc5NjkifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6My",
    "wicGNyX3ZhbHVlIjoiM2Q0NThjZmU1NWNjMDNlYTFmNDQzZjE1NjJiZWVjOGRmNTFjNzV",
    "lMTRhOWZjZjlhNzIzNGExM2YxOThlNzk2OSIsInJlcGxheV92YWx1ZSI6IjNkNDU4Y2ZlN",
    "TVjYzAzZWExZjQ0M2YxNTYyYmVlYzhkZjUxYzc1ZTE0YTlmY2Y5YTcyMzRhMTNmMTk4ZTc",
    "5NjkifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6NCwicGNyX3ZhbHVlIjoiO",
    "GVkMTJjNDE1MDU2MzYyYzdhNGQ0MDNlNmUyYWNhZGYwOTBlNzhiZmI0Nzk4YTg3YjBhMzI",
    "3YzgzODA2NDkzMSIsInJlcGxheV92YWx1ZSI6IjhlZDEyYzQxNTA1NjM2MmM3YTRkNDAzZ",
    "TZlMmFjYWRmMDkwZTc4YmZiNDc5OGE4N2IwYTMyN2M4MzgwNjQ5MzEifSx7ImlzX21hdGN",
    "oZWQiOnRydWUsInBjcl9pbmRleCI6NSwicGNyX3ZhbHVlIjoiNjYxMjFkNWJjZGI4YWI2Z",
    "DYyOGI0OTgyNzU5MGFjOGUxZjJmMDllMjZhYTJkMWRkMWNmZWM1MzU4ODU0Y2QzYSIsInJ",
    "lcGxheV92YWx1ZSI6IjY2MTIxZDViY2RiOGFiNmQ2MjhiNDk4Mjc1OTBhYzhlMWYyZjA5Z",
    "TI2YWEyZDFkZDFjZmVjNTM1ODg1NGNkM2EifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9",
    "pbmRleCI6NiwicGNyX3ZhbHVlIjoiM2Q0NThjZmU1NWNjMDNlYTFmNDQzZjE1NjJiZWVjO",
    "GRmNTFjNzVlMTRhOWZjZjlhNzIzNGExM2YxOThlNzk2OSIsInJlcGxheV92YWx1ZSI6IjN",
    "kNDU4Y2ZlNTVjYzAzZWExZjQ0M2YxNTYyYmVlYzhkZjUxYzc1ZTE0YTlmY2Y5YTcyMzRhM",
    "TNmMTk4ZTc5NjkifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6NywicGNyX3Z",
    "hbHVlIjoiNzRmYTJjMDY3ODkyZmFhNzRiZmIwY2FmYWNjNGM3MTAyZGQyYzljZjczZWZkZ",
    "mE0MWYwN2ZkZmM3YzFlZWExYiIsInJlcGxheV92YWx1ZSI6Ijc0ZmEyYzA2Nzg5MmZhYTc",
    "0YmZiMGNhZmFjYzRjNzEwMmRkMmM5Y2Y3M2VmZGZhNDFmMDdmZGZjN2MxZWVhMWIifV19L",
    "CJzZWN1cmVfYm9vdCI6Ik5BIn0sImlhdCI6MTc0NDk1ODA3OTU3MiwiZXhwIjoxNzQ0OTU",
    "4Njc5NTcyLCJpc3MiOiJpc3MiLCJqdGkiOiIwMGJhNjlkMy1kNGM2LTQ2ZjEtYmNmMS1lN",
    "GZkMjNkODVlODQiLCJ2ZXIiOiIxLjAiLCJuYmYiOjE3NDQ5NTgwNzk1NzMsImVhdF9wcm9",
    "maWxlIjoiZWF0X3Byb2ZpbGUifQ.q-CdDXeVoE4IMDqKae76P5wAnyrETAnkc394rQB63a",
    "iGHJA8HuEWM5EQ6nuKhoB0BomQahi8NiFYFIn-ldK2wk_HyTDSWvNd4ZMpl4RrEE403S_T",
    "Bmu_ZrY_aPhpTgUbH5Rdk-4tqXhDcJ171YxpPngbZ6hfeiPE9gHo4oAeZl7sULFsGcj64X",
    "5aVPRAGw-rdaA_4gKXvICnlm6U3naRxNXOd4nZKUERXqlExM8uB-x1f87y0tyD5BOQQQqt",
    "P7fIJuN8vubWbtj3ShQ7jIaFl2AdEMDcId8IapECNWP8VpTcu2rK-dHL8tGI0K8XfUFYtw",
    "LZ02HYnz86IqCjbFYhpg");
    let json_value = serde_json::json!({
        "service_version": "1.0.0",
        "tokens": [
            {
                "node_id": "TPM AK",
                "token": long_token
            }
        ]
    });

    // let client = Client::instance();
    // // Send the evidence to the attestation server
    // let response = client
    //     .request(Method::POST, "/attest", Some(serde_json::to_value(evidence)?))
    //     .await
    //     .map_err(|e| ChallengeError::NetworkError(format!("Failed to verify evidence: {}", e)))?;

    // // Parse the server's JSON response
    // let json_value = response
    //     .json::<serde_json::Value>()
    //     .await
    //     .map_err(|e| ChallengeError::RequestParseError(format!("Failed to parse verify response: {}", e)))?;

    // Check for error message in the response
    if let Some(msg) = json_value.get("message").and_then(|v| v.as_str()) {
        if !msg.is_empty() {
            return Err(ChallengeError::ServerError(msg.to_string()));
        }
    }

    // Extract the tokens array from the response
    let tokens = match json_value.get("tokens") {
        Some(val) => val.as_array().ok_or_else(|| ChallengeError::RequestParseError("tokens field is not array".to_string()))?,
        None => return Err(ChallengeError::TokenNotReceived),
    };
    let mut node_tokens = Vec::new();
    // For each token, extract node_id and token value
    for t in tokens {
        let node_id = t.get("node_id").and_then(|v| v.as_str()).ok_or_else(|| ChallengeError::RequestParseError("token.node_id missing or not string".to_string()))?.to_string();
        let token_val = t.get("token").cloned().unwrap_or(serde_json::Value::Null);
        node_tokens.push(NodeToken { node_id, token: token_val });
    }

    Ok(node_tokens)
}

/// Main entry for the attestation challenge process
pub async fn do_challenge(
    attester_info: &Option<Vec<AttesterInfo>>,
    attester_data: &Option<String>,
) -> Result<bool, ChallengeError> {
    let _tpm_lock = acquire_tpm_lock()?;
    log::info!("Starting challenge request.");

    let nonce = get_nonce_from_server(
        env!("CARGO_PKG_VERSION"),
        attester_info,
    ).await?;

    let evidences = collect_evidences_core(
        attester_info,
        &Some(nonce.value.clone()),
    )?;

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
    set_cached_tokens(node_tokens);
    log::info!("Successfully obtained and saved tokens from server");
    Ok(true)
}