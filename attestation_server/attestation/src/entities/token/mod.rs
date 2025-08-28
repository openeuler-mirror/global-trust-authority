use serde::{Deserialize, Serialize};

pub mod ear_token;
pub mod eat_token;
pub mod token_trait;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyInfo {
    pub appraisal_policy_id: String,
    pub policy_version: i32,
    pub policy_matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenResponse {
    pub node_id: String,
    pub token: String,
}
