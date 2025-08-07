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
use validator::{Validate, ValidationError};
use crate::constants::VALID_TYPES;

#[derive(Deserialize, Serialize, Validate, Debug)]
pub struct AttestRequest {
    pub message: Option<String>,

    #[validate(length(min = 1, max = 50))]
    pub agent_version: Option<String>,

    #[validate(length(min = 1), custom(function = "validate_measurements"))]
    pub measurements: Vec<Measurement>,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct Measurement {
    #[validate(length(min = 1, max = 255))]
    pub node_id: String,

    pub nonce: Option<String>,

    #[validate(custom(function = "validate_nonce_type"))]
    pub nonce_type: Option<String>,

    pub attester_data: Option<serde_json::Value>,

    #[validate(length(min = 1), custom(function = "validate_evidences"))]
    pub evidences: Vec<Evidence>,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone, Default)]
pub struct Nonce {
    pub iat: u64,
    pub value: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct Evidence {
    #[validate(length(min = 1, max = 255))]
    pub attester_type: String,

    pub evidence: serde_json::Value,

    #[validate(custom(function = "validate_policy_ids"), length(min = 1, max = 10))]
    pub policy_ids: Option<Vec<String>>,
}

fn validate_nonce_type(nonce_type: &str) -> Result<(), ValidationError> {
    if !VALID_TYPES.contains(&nonce_type) {
        let mut err = ValidationError::new("invalid_nonce_type");
        err.message = Some(std::borrow::Cow::Owned("nonce_type must be one of: ignore, user, verifier".to_string()));
        return Err(err);
    }
    Ok(())
}

fn validate_measurements(measurements: &Vec<Measurement>) -> Result<(), ValidationError> {
    for measurement in measurements {
        if let Err(errors) = measurement.validate() {
            let mut err = ValidationError::new("invalid_measurement");
            err.message = Some(std::borrow::Cow::Owned(format!("Invalid measurement: {:?}", errors)));
            return Err(err);
        }
    }
    Ok(())
}

fn validate_evidences(evidences: &Vec<Evidence>) -> Result<(), ValidationError> {
    for evidence in evidences {
        if let Err(errors) = evidence.validate() {
            let mut err = ValidationError::new("invalid_evidence");
            err.message = Some(std::borrow::Cow::Owned(format!("Invalid evidence: {:?}", errors)));
            return Err(err);
        }
    }
    Ok(())
}

fn validate_policy_ids(policy_ids: &Vec<String>) -> Result<(), ValidationError> {
    for policy_id in policy_ids {
        if policy_id.len() > 36 || policy_id.is_empty() {
            let mut err = ValidationError::new("length");
            err.message =
                Some(std::borrow::Cow::Owned("policy_id length must be between 1 and 36 characters".to_string()));
            return Err(err);
        }
    }
    Ok(())
}
