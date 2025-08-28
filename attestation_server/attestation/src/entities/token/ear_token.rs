use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::constants::VERIFIER_DEVELOPER;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EarToken {
    pub matched_policy: Vec<String>,
    pub unmatched_policy: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ueid: Option<String>,
    #[serde(rename = "ear.verifier-id")]
    pub ear_verifier_id: EarTokenVerifierId,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ear.raw-evidence")]
    pub ear_raw_evidence: Option<serde_json::Value>,
    pub submods: Vec<EarSubmodResult>,
}

impl EarToken {
    pub fn new() -> Self {
        Self {
            ear_verifier_id: EarTokenVerifierId {
                developer: VERIFIER_DEVELOPER.to_string(),
                version: "v1.0.0".to_string(),
            },
            matched_policy: Vec::new(),
            unmatched_policy: Vec::new(),
            ueid: None,
            ear_raw_evidence: None,
            submods: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EarTokenVerifierId {
    pub developer: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EarSubmodResult {
    #[serde(flatten)]
    pub ear_attester_results: HashMap<String, EarAttesterResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EarAttesterResult {
    #[serde(rename = "ear.status")]
    pub ear_status: String,
    #[serde(rename = "ear.trustworthiness-vector")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ear_trustworthiness_vector: Option<Vec<EarTrustworthinessVector>>,
    #[serde(rename = "ear.appraisal-policy-id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ear_appraisal_policy_id: Option<String>,
    #[serde(rename = "ear.gta-annotated-evidence")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ear_gta_annotated_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EarTrustworthinessVector {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executables: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<i32>,
}