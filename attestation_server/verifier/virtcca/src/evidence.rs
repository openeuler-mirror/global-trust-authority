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
use openssl::x509::X509;
use openssl::asn1::Asn1Time;
use plugin_manager::PluginError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering::{Greater, Less};

use super::log_verifier::LogResult;
use crate::constants::{VCCA_EQUIPMENT_ROOT_CA_ECCP521, VCCA_EQUIPMENT_ROOT_CA_RSA, VCCA_IT_PRODUCT_CA_ECCP521, VCCA_IT_PRODUCT_CA_RSA};
use crate::tokens::VccaToken;
use crate::verifier::VirtCCAPlugin;
use crate::log_verifier::verify_all_logs;

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub log_type: String,
    pub log_data: String,
}

/// Represents the VirtCCA evidence structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct VritCCAEvidence {
    pub vcca_token: String,
    pub dev_cert: String,
    pub logs: Option<Vec<Log>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceResult {
    log_info: Vec<LogResult>,
    token_info: Vec<Value>,
}

impl VritCCAEvidence {
    /// Creates a `VritCCAEvidence` instance from a JSON value.
    ///
    /// # Parameters
    /// - `json_value`: The JSON value to parse.
    ///
    /// # Returns
    /// A `Result` containing the `VritCCAEvidence` or a `PluginError`.
    pub fn from_json_value(json_value: &Value) -> Result<Self, PluginError> {
        let required_fields = &["vcca_token", "dev_cert"];
        for field in required_fields {
            if json_value.get(*field).is_none() {
                return Err(PluginError::InputError(format!("Missing required field: {}", field)));
            }
        }

        let vcca_token = json_value["vcca_token"]
            .as_str()
            .ok_or(PluginError::InputError("vcca_token must be a string".to_string()))?
            .to_string();

        let dev_cert = json_value["dev_cert"]
            .as_str()
            .ok_or(PluginError::InputError("dev_cert must be a string".to_string()))?
            .to_string();

        let logs = if let Some(log_array) = json_value.get("logs") {
            if !log_array.is_array() {
                return Err(PluginError::InputError("logs must be an array".to_string()));
            }
            let mut parsed_logs = Vec::new();
            for log_value in log_array.as_array().unwrap() {
                let log_type = log_value
                    .get("log_type")
                    .and_then(|v| v.as_str())
                    .ok_or(PluginError::InputError("log_type must be a string".to_string()))?
                    .to_string();

                let log_data = log_value
                    .get("log_data")
                    .and_then(|v| v.as_str())
                    .ok_or(PluginError::InputError("log_data must be a string".to_string()))?
                    .to_string();

                parsed_logs.push(Log { log_type, log_data });
            }
            Some(parsed_logs)
        } else {
            None
        };

        Ok(VritCCAEvidence { vcca_token, dev_cert, logs })
    }

    fn verify_cert_chain(&self) -> Result<(), PluginError> {
        let dev_cert_bytes = general_purpose::STANDARD.decode(&self.dev_cert)
            .map_err(|e| PluginError::InternalError(format!("Failed to decode base64 device certificate: {}", e)))?;
        let dev_cert_x509 = X509::from_der(&dev_cert_bytes)
            .map_err(|e| PluginError::InternalError(format!("Failed to parse device certificate: {}", e)))?;
        let dev_pk = dev_cert_x509
            .public_key()
            .map_err(|e| PluginError::InternalError(format!("Failed to get device public key: {}", e)))?;
        let is_rsa = dev_pk.rsa().is_ok();
        let root_ca_pem = if is_rsa { VCCA_EQUIPMENT_ROOT_CA_RSA } else { VCCA_EQUIPMENT_ROOT_CA_ECCP521 };
        let product_ca_pem = if is_rsa { VCCA_IT_PRODUCT_CA_RSA } else { VCCA_IT_PRODUCT_CA_ECCP521 };

        let device_cert = dev_cert_x509;
        let product_cert = X509::from_pem(product_ca_pem.as_bytes())
            .map_err(|e| PluginError::InternalError(format!("Failed to parse product CA: {}", e)))?;
        let root_cert = X509::from_pem(root_ca_pem.as_bytes())
            .map_err(|e| PluginError::InternalError(format!("Failed to parse root CA: {}", e)))?;

        let now = Asn1Time::days_from_now(0).map_err(|e| PluginError::InternalError(format!("Failed to get current time: {}", e)))?;

        // Check device cert validity
        if now.compare(&device_cert.not_before()).map_err(|e| PluginError::InputError(e.to_string()))? != Greater ||
           now.compare(&device_cert.not_after()).map_err(|e| PluginError::InputError(e.to_string()))? != Less {
            return Err(PluginError::InputError("Device certificate is expired or not yet valid".to_string()));
        }

        // Check product cert validity
        if now.compare(&product_cert.not_before()).map_err(|e| PluginError::InputError(e.to_string()))? != Greater ||
           now.compare(&product_cert.not_after()).map_err(|e| PluginError::InputError(e.to_string()))? != Less {
            return Err(PluginError::InputError("Product certificate is expired or not yet valid".to_string()));
        }

        // Check root cert validity
        if now.compare(&root_cert.not_before()).map_err(|e| PluginError::InputError(e.to_string()))? != Greater ||
           now.compare(&root_cert.not_after()).map_err(|e| PluginError::InputError(e.to_string()))? != Less {
            return Err(PluginError::InputError("Root certificate is expired or not yet valid".to_string()));
        }

        // verify dev_cert by product_cert
        let product_pk = product_cert.public_key().map_err(|e| PluginError::InternalError(e.to_string()))?;
        let ret = device_cert
            .verify(product_pk.as_ref())
            .map_err(|e| PluginError::InternalError(format!("Failed to verify device cert by product cert: {}", e)))?;
        if !ret {
            return Err(PluginError::InternalError("Verify device cert by product cert failed".to_string()));
        }

        // verify product_cert by root_cert
        let root_pk_product = root_cert.public_key().map_err(|e| PluginError::InternalError(e.to_string()))?;
        let ret = product_cert
            .verify(root_pk_product.as_ref())
            .map_err(|e| PluginError::InternalError(format!("Failed to verify product cert by root cert: {}", e)))?;
        if !ret {
            return Err(PluginError::InternalError("Verify product cert by root cert failed".to_string()));
        }

        // verify self signed root_cert
        let root_pk_self = root_cert.public_key().map_err(|e| PluginError::InternalError(e.to_string()))?;
        let ret = root_cert
            .verify(root_pk_self.as_ref())
            .map_err(|e| PluginError::InternalError(format!("Failed to verify self signed root cert: {}", e)))?;
        if !ret {
            return Err(PluginError::InternalError("Verify self signed root cert failed".to_string()));
        }

        Ok(())
    }

    /// Verifies the evidence asynchronously.
    ///
    /// # Parameters
    /// - `user_id`: The user identifier.
    /// - `_node_id`: Optional node identifier (currently unused).
    /// - `nonce`: Optional nonce for verification.
    /// - `plugin`: Reference to the `VirtCCAPlugin`.
    ///
    /// # Returns
    /// A `Result` containing the verification result as `Value` or a `PluginError`.
    pub async fn verify(
        &self,
        user_id: &str,
        _node_id: Option<&str>,
        nonce: Option<&[u8]>,
        plugin: &VirtCCAPlugin,
    ) -> Result<Value, PluginError> {
        // Certificate chain for verifying equipment certificates
        self.verify_cert_chain()?;
        
        // verify cvm_token
        let decoded_evidence = general_purpose::STANDARD
            .decode(&self.vcca_token)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 token: {}", e)))?;
        let mut vcca_token = VccaToken::new(&decoded_evidence)?;
        vcca_token.verify_cvm_token(nonce)?;
        let token_info = vcca_token.to_json_value();
        
        // verify log
        let log_results = verify_all_logs(
            self.logs.as_ref(),
            vcca_token.tokens.cvm_token.rem.clone(),
            plugin,
            user_id,
        ).await?;

        let mut evidence_result_map = serde_json::Map::new();
        if let Some(token_info_map) = token_info.as_object() {
            evidence_result_map.extend(token_info_map.clone());
        }
        let log_results_vec = log_results.into_iter().map(|log_result| log_result.to_json_value()).collect::<Vec<Value>>();
        for log_value in log_results_vec {
            if let Some(log_map) = log_value.as_object() {
                evidence_result_map.extend(log_map.clone());
            }
        }
        let evidence_result = Value::Object(evidence_result_map);

        Ok(evidence_result)
    }
}
