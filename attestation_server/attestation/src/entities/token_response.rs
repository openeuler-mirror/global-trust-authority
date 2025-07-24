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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::entities::attest_request::Nonce;
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub node_id: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub nonce_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intuse: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eat_nonce: Option<Value>,
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
