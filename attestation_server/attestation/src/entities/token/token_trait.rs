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

use serde::{Deserialize, Serialize};

use crate::entities::attest_request::Measurement;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AttesterResult {
    Eat(super::eat_token::EatAttesterResult),
    Ear(super::ear_token::EarAttesterResult),
}

pub enum TokenType {
    Eat(super::eat_token::EatToken),
    Ear(super::ear_token::EarToken),
}

pub trait Token: Send + Sync {
    fn create_evidence_response(
        &mut self,
        verify_results: Vec<bool>,
        raw_evidence: Option<serde_json::Value>,
        policy_info: Vec<super::PolicyInfo>,
    ) -> AttesterResult;
    fn create_attestation_response(
        &self,
        evidence_token_responses: &HashMap<String, AttesterResult>,
        nonce_type: &str,
        nonce: &Option<String>,
        measurement: &Measurement,
    ) -> TokenType;
}