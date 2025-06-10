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
use crate::entities::request_body::validator::Validator;

#[derive(Clone, Deserialize, Validate, Serialize)]
#[validate(schema(function = "validate_rv_update_body"))]
pub struct RvUpdateReqBody {
    #[validate(length(min = 1, max = 32))]
    pub id: String,
    
    /// Reference value name
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,

    /// Reference value description
    #[validate(length(max = 512))]
    pub description: Option<String>,

    /// challenge plugin type
    pub attester_type: Option<String>,

    /// content
    pub content: Option<String>,

    /// is default reference value
    pub is_default: Option<bool>,
}

fn validate_rv_update_body(body: &RvUpdateReqBody) -> Result<(), ValidationError> {
    // Ensure at least one field is updated
    if body.name.is_none() &&
        body.description.is_none() &&
        body.attester_type.is_none() &&
        body.content.is_none() &&
        body.is_default.is_none() {
        return Err(ValidationError::new("there is no field need to be updated"));
    }
    Validator::validate_attester_type_could_none(&body.attester_type)?;
    Ok(())
}
