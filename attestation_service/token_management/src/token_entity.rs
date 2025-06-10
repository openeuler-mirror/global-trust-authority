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

use jsonwebtoken::Header;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// verify token response
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyTokenResponse {
    verification_pass: bool,
    token_body: Option<Value>,
    token_header: Option<Header>
}

impl VerifyTokenResponse {
    pub fn new(verification_pass: bool, token_body: Option<Value>, token_header: Option<Header>) -> Self {
        Self { verification_pass, token_body, token_header }
    }
}