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

    fn parse_cert(&self, cert_bytes: &[u8], cert_type: &str, is_platform: bool) -> Result<X509, PluginError> {
        if is_platform {
            X509::from_pem(cert_bytes)
                .map_err(|e| PluginError::InputError(format!("Failed to parse {} certificate: {}", cert_type, e)))
        } else {
            X509::from_der(cert_bytes)
                .map_err(|e| PluginError::InputError(format!("Failed to parse {} certificate: {}", cert_type, e)))
        }
    }

    fn check_validity(&self, cert: &X509, cert_type: &str) -> Result<(), PluginError> {
        let now = Asn1Time::days_from_now(0)
            .map_err(|e| PluginError::InputError(format!("Failed to get current time: {}", e)))?;

        if now.compare(cert.not_before()).map_err(|e| PluginError::InputError(e.to_string()))? != Greater ||
           now.compare(cert.not_after()).map_err(|e| PluginError::InputError(e.to_string()))? != Less {
            return Err(PluginError::InputError(format!("{} certificate is expired or not yet valid", cert_type)));
        }
        Ok(())
    }

    fn verify_cert(&self, cert: &X509, issuer_cert: &X509, cert_type: &str) -> Result<(), PluginError> {
        let issuer_pk = issuer_cert.public_key()
            .map_err(|e| PluginError::InputError(e.to_string()))?;

        if !cert.verify(issuer_pk.as_ref())
            .map_err(|e| PluginError::InputError(format!("Failed to verify {} cert: {}", cert_type, e)))? {
            return Err(PluginError::InputError(format!("Verify {} cert failed", cert_type)));
        }
        Ok(())
    }

    fn verify_cert_chain(&self, is_platform: bool) -> Result<(), PluginError> {
        let dev_cert_bytes = general_purpose::STANDARD.decode(&self.dev_cert)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 device certificate: {}", e)))?;
        let dev_cert = self.parse_cert(&dev_cert_bytes, "device", is_platform)?;

        let root_ca_pem = if !is_platform { VCCA_EQUIPMENT_ROOT_CA_RSA } else { VCCA_EQUIPMENT_ROOT_CA_ECCP521 };
        let product_ca_pem = if !is_platform { VCCA_IT_PRODUCT_CA_RSA } else { VCCA_IT_PRODUCT_CA_ECCP521 };

        let product_cert = X509::from_pem(product_ca_pem.as_bytes())
            .map_err(|e| PluginError::InputError(format!("Failed to parse product CA: {}", e)))?;
        let root_cert = X509::from_pem(root_ca_pem.as_bytes())
            .map_err(|e| PluginError::InputError(format!("Failed to parse root CA: {}", e)))?;

        self.check_validity(&dev_cert, "Device")?;
        self.check_validity(&product_cert, "Product")?;
        self.check_validity(&root_cert, "Root")?;

        self.verify_cert(&dev_cert, &product_cert, "device")?;
        self.verify_cert(&product_cert, &root_cert, "product")?;
        self.verify_cert(&root_cert, &root_cert, "root self-signed")?;

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
        let decoded_evidence = general_purpose::STANDARD
            .decode(&self.vcca_token)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 token: {}", e)))?;
        let mut vcca_token = VccaToken::new(&decoded_evidence)?;

        // Certificate chain for verifying equipment certificates
        self.verify_cert_chain(vcca_token.tokens.is_platform)?;

        // verify vcca_token
        vcca_token.verify_vcca_token(nonce, &self.dev_cert)?;
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
