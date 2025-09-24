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

use crate::entities::token::token_trait::Token;
use crate::entities::token::ear_token::EarToken;
use crate::entities::token::eat_token::EatToken;
use crate::error::attestation_error::AttestationError;

pub enum TokenType {
    Eat,
    Ear,
}

pub struct TokenFactory;

impl TokenFactory {
    pub fn new() -> Self {
        Self
    }

    pub fn create_token(&self, token_fmt: &str) -> Result<Box<dyn Token>, AttestationError> {
        match token_fmt {
            "eat" => Ok(Box::new(EatToken::new())),
            "ear" => Ok(Box::new(EarToken::new())),
            _ => Err(AttestationError::InvalidParameter(token_fmt.to_string())),
        }
    }
}