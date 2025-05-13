use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::entities::attest_request::Nonce;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub node_id: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intuse: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eat_nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ueid: Option<String>,
    #[serde(flatten)]
    pub results: HashMap<String, AttesterResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttesterResult {
    pub attestation_status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_info: Vec<PolicyInfo>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyInfo {
    pub appraisal_policy_id: String,
    pub policy_version: i32,
    pub policy_matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<serde_json::Value>,
}
