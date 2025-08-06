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

use plugin_manager::PluginError;
use sec_gear::virtcca::Evidence;
use serde_json::{json, Value};

/// Represents a VCCA token.
pub struct VccaToken {
    pub tokens: Evidence,
}

impl VccaToken {
    /// Creates a new `VccaToken` from the provided byte slice.
    ///
    /// # Parameters
    /// - `vcca_token`: A byte slice containing the encoded token.
    ///
    /// # Returns
    /// A `Result` containing the `VccaToken` or a `PluginError`.
    pub fn new(vcca_token: &[u8]) -> Result<Self, PluginError> {
        let evidence = Evidence::decode(vcca_token.to_vec())
            .map_err(|e| PluginError::InternalError(e.to_string()))?;
        Ok(Self {
            tokens: evidence,
        })
    }

    /// Verifies the CVM token, optionally checking against a nonce.
    ///
    /// # Parameters
    /// - `nonce`: Optional nonce to verify against the token's challenge.
    ///
    /// # Returns
    /// A `Result` indicating success or a `PluginError`.
    pub fn verify_cvm_token(&mut self, nonce: Option<&[u8]>) -> Result<(), PluginError> {
        // Verify challenge matches nonce if provided
        if let Some(nonce) = nonce {
            let nonce_len = nonce.len();
            let token_challenge = &self.tokens.cvm_token.challenge[..nonce_len];
            if token_challenge != nonce {
                return Err(PluginError::InputError("Cvm token challenge does not match nonce".to_string()));
            }
        }
        
        self.tokens.verify_cose_sign1()
            .map_err(|e| PluginError::InputError(e.to_string()))?;
        Ok(())
    }

    /// Converts the `VccaToken` to a JSON value.
    ///
    /// # Returns
    /// A `Value` representing the token in JSON format.
    pub fn to_json_value(&self) -> Value {
        let mut json_map = serde_json::Map::new();
        json_map.insert("vcca_rpv".to_string(), json!(hex::encode(self.tokens.cvm_token.rpv)));
        json_map.insert("vcca_rim".to_string(), json!(hex::encode(self.tokens.cvm_token.rim.clone())));
        for (i, rem_val) in self.tokens.cvm_token.rem.iter().enumerate() {
            json_map.insert(format!("vcca_rem{}", i), json!(hex::encode(rem_val)));
        }
        json_map.insert("vcca_cvm_token_hash_alg".to_string(), json!(self.tokens.cvm_token.hash_alg));

        json!(json_map)
    }
}
