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
use base64::{engine::general_purpose, Engine as _};
use openssl::{pkey::PKey, x509::X509};
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
        let evidence = Evidence::decode(vcca_token.to_vec()).map_err(|e| PluginError::InternalError(e.to_string()))?;
        Ok(Self { tokens: evidence })
    }

    pub fn verify_vcca_token(&mut self, nonce: Option<&[u8]>, dev_cert: &String) -> Result<(), PluginError> {
        if self.tokens.is_platform {
            let dev_cert_bytes = general_purpose::STANDARD
                .decode(dev_cert)
                .map_err(|e| PluginError::InputError(format!("Failed to decode base64 device certificate: {}", e)))?;
            self.verify_platform_token(&dev_cert_bytes)?;
        }
        self.verify_cvm_token(nonce)?;
        Ok(())
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

        if self.tokens.is_platform {
            self.tokens
                .verfiy_cvm_challenge(&self.tokens.platform_token.challenge, &self.tokens.cvm_token.pub_key)
                .map_err(|e| PluginError::InputError(e.to_string()))?;
        }

        let pkey = PKey::public_key_from_der(&self.tokens.cvm_token.pub_key)
            .or_else(|_| self.tokens.raw_ec_public_key_to_pkey())
            .map_err(|e| PluginError::InternalError(e.to_string()))?;
        Evidence::verify_cose_sign1(&mut self.tokens.cvm_envelop, &pkey)
            .map_err(|e| PluginError::InputError(e.to_string()))?;
        Ok(())
    }

    fn verify_platform_token(&mut self, dev_cert: &[u8]) -> Result<(), PluginError> {
        let pkey = X509::from_pem(dev_cert)
            .map_err(|e| PluginError::InputError(e.to_string()))?
            .public_key()
            .map_err(|e| PluginError::InputError(e.to_string()))?;
        Evidence::verify_cose_sign1(&mut self.tokens.platform_envelop, &pkey)
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
        if self.tokens.is_platform {
            json_map.insert("vcca_platform_token_profile".to_string(), json!(self.tokens.platform_token.profile));
            json_map.insert("vcca_platform_token_implementation".to_string(),json!(hex::encode(self.tokens.platform_token.implementation)),);
            json_map.insert("vcca_platform_token_instance".to_string(), json!(hex::encode(self.tokens.platform_token.instance)));
            json_map.insert("vcca_platform_token_config".to_string(), json!(hex::encode(self.tokens.platform_token.config.clone())));
            json_map.insert("vcca_platform_token_lifecycle".to_string(), json!(self.tokens.platform_token.lifecycle));
            json_map.insert("vcca_platform_token_sw_components".to_string(), json!(self.tokens.platform_token.sw_components));
            json_map.insert("vcca_platform_token_verification_service".to_string(), json!(self.tokens.platform_token.verification_service));
            json_map.insert("vcca_platform_token_hash_algo".to_string(), json!(self.tokens.platform_token.hash_algo));
        }
        json!(json_map)
    }
}
