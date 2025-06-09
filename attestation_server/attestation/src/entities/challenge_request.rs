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

use validator::{Validate, ValidationError};
use serde::Deserialize;

#[derive(Deserialize, Validate, Debug)]
pub struct ChallengeRequest {
    #[validate(length(min = 1, max = 50))]
    pub agent_version: Option<String>,

    #[validate(length(min = 1), custom(function = "validate_attester_type_elements"))]
    pub attester_type: Vec<String>,
}

fn validate_attester_type_elements(attester_type: &Vec<String>) -> Result<(), ValidationError> {
    for element in attester_type {
        if element.len() > 255 || element.len() == 0 {
            let mut err = ValidationError::new("length");
            err.message = Some(std::borrow::Cow::Owned("Element length more than 255 or equal to 0".to_string()));
            return Err(err);
        }
    }
    Ok(())
}
