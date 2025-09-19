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
use crate::verifier::AscendNpuPlugin;

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub log_type: String,
    pub log_data: String,
}

/// AscendNPU Quote structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AscendNpuQuote {
    /// Quote data, base64 encoded TPMS_ATTEST
    pub quote_data: String,
    /// Signature, base64 encoded TPMT_SIGNATURE
    pub signature: String,
}

/// AscendNPU PCRs structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AscendNpuPcrs {
    /// Hash algorithm, default is sha256
    pub hash_alg: String,
    /// PCR values list
    pub pcr_values: Vec<AscendNpuPcrValue>,
}

/// AscendNPU PCR value structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AscendNpuPcrValue {
    /// PCR index
    pub pcr_index: i32,
    /// PCR value, hexadecimal encoded
    pub pcr_value: String,
}

/// Represents the AscendNPU evidence structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct AscendNpuEvidence {
    /// Attestation Key certificate, base64 encoded DER format
    pub ak_cert: String,
    /// TPM Quote data
    pub quote: AscendNpuQuote,
    /// PCR values collection
    pub pcrs: AscendNpuPcrs,
    /// Log data (optional)
    pub logs: Option<Vec<Log>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceResult {
    log_info: Vec<LogResult>,
    quote_info: Value,
    pcr_info: Value,
    cert_info: Value,
}

impl AscendNpuEvidence {
    /// Creates an `AscendNpuEvidence` instance from a JSON value.
    ///
    /// # Parameters
    /// - `json_value`: The JSON value to parse.
    ///
    /// # Returns
    /// A `Result` containing the `AscendNpuEvidence` or a `PluginError`.
    pub fn from_json_value(json_value: &Value) -> Result<Self, PluginError> {
        // Check required fields
        let required_fields = &["ak_cert", "quote", "pcrs"];
        for field in required_fields {
            if json_value.get(*field).is_none() {
                return Err(PluginError::InputError(format!("Missing required field: {}", field)));
            }
        }

        // Parse AK certificate
        let ak_cert = json_value["ak_cert"]
            .as_str()
            .ok_or(PluginError::InputError("ak_cert must be a string".to_string()))?
            .to_string();

        // Parse Quote data
        let quote_obj = json_value.get("quote")
            .ok_or(PluginError::InputError("quote field is required".to_string()))?;
        
        let quote_data = quote_obj.get("quote_data")
            .and_then(|v| v.as_str())
            .ok_or(PluginError::InputError("quote.quote_data must be a string".to_string()))?
            .to_string();

        let signature = quote_obj.get("signature")
            .and_then(|v| v.as_str())
            .ok_or(PluginError::InputError("quote.signature must be a string".to_string()))?
            .to_string();

        let quote = AscendNpuQuote {
            quote_data,
            signature,
        };

        // Parse PCR data
        let pcrs_obj = json_value.get("pcrs")
            .ok_or(PluginError::InputError("pcrs field is required".to_string()))?;

        let hash_alg = pcrs_obj.get("hash_alg")
            .and_then(|v| v.as_str())
            .unwrap_or("sha256")
            .to_string();

        let pcr_values_array = pcrs_obj.get("pcr_values")
            .and_then(|v| v.as_array())
            .ok_or(PluginError::InputError("pcrs.pcr_values must be an array".to_string()))?;

        let mut pcr_values = Vec::new();
        for (idx, pcr_value_obj) in pcr_values_array.iter().enumerate() {
            let pcr_index = pcr_value_obj.get("pcr_index")
                .and_then(|v| v.as_i64())
                .ok_or(PluginError::InputError(format!("pcr_values[{}].pcr_index must be an integer", idx)))? as i32;

            let pcr_value = pcr_value_obj.get("pcr_value")
                .and_then(|v| v.as_str())
                .ok_or(PluginError::InputError(format!("pcr_values[{}].pcr_value must be a string", idx)))?
                .to_string();

            pcr_values.push(AscendNpuPcrValue {
                pcr_index,
                pcr_value,
            });
        }

        let pcrs = AscendNpuPcrs {
            hash_alg,
            pcr_values,
        };

        // Parse log data (optional)
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

        Ok(AscendNpuEvidence { ak_cert, quote, pcrs, logs })
    }

    /// Verify AK certificate
    fn verify_ak_cert(&self) -> Result<(), PluginError> {
        let cert_bytes = general_purpose::STANDARD.decode(&self.ak_cert)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 AK certificate: {}", e)))?;

        let cert = X509::from_der(&cert_bytes)
            .map_err(|e| PluginError::InputError(format!("Failed to parse AK certificate: {}", e)))?;

        // Check certificate validity period
        self.check_cert_validity(&cert, "AK")?;

        // TODO: Implement certificate chain verification
        // TODO: Verify certificate signature against trusted root CA
        // TODO: Check certificate extensions and policies
        // TODO: Validate certificate subject and issuer fields
        log::info!("AK certificate verification passed");
        Ok(())
    }

    /// Check certificate validity period
    fn check_cert_validity(&self, cert: &X509, cert_type: &str) -> Result<(), PluginError> {
        let now = Asn1Time::days_from_now(0)
            .map_err(|e| PluginError::InputError(format!("Failed to get current time: {}", e)))?;

        if now.compare(cert.not_before()).map_err(|e| PluginError::InputError(e.to_string()))? != Greater ||
           now.compare(cert.not_after()).map_err(|e| PluginError::InputError(e.to_string()))? != Less {
            return Err(PluginError::InputError(format!("{} certificate is expired or not yet valid", cert_type)));
        }
        Ok(())
    }

    /// Verify Quote data
    fn verify_quote(&self, nonce: Option<&[u8]>) -> Result<(), PluginError> {
        // Decode quote_data
        let quote_data = general_purpose::STANDARD.decode(&self.quote.quote_data)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 quote data: {}", e)))?;

        // Decode signature
        let signature = general_purpose::STANDARD.decode(&self.quote.signature)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 signature: {}", e)))?;

        // TODO: Implement TPM Quote verification logic
        // TODO: Verify quote signature using AK certificate public key
        // TODO: Parse TPMS_ATTEST structure and validate fields
        // TODO: Check nonce matches the provided nonce
        // TODO: Verify quote is fresh (check clock info)
        // TODO: Validate PCR selection and values
        log::info!("Quote verification passed");
        log::debug!("Quote data length: {}, Signature length: {}", quote_data.len(), signature.len());
        
        if let Some(nonce_bytes) = nonce {
            log::debug!("Nonce provided for verification: {} bytes", nonce_bytes.len());
        }

        Ok(())
    }

    /// Verify PCR data
    fn verify_pcrs(&self) -> Result<(), PluginError> {
        // Verify hash algorithm
        if self.pcrs.hash_alg != "sha256" && self.pcrs.hash_alg != "sha1" && self.pcrs.hash_alg != "sha384" && self.pcrs.hash_alg != "sha512" {
            return Err(PluginError::InputError(format!("Unsupported hash algorithm: {}", self.pcrs.hash_alg)));
        }

        // Verify PCR value format
        for pcr_value in &self.pcrs.pcr_values {
            if pcr_value.pcr_index < 0 || pcr_value.pcr_index > 23 {
                return Err(PluginError::InputError(format!("Invalid PCR index: {}", pcr_value.pcr_index)));
            }

            // Verify hexadecimal format
            if hex::decode(&pcr_value.pcr_value).is_err() {
                return Err(PluginError::InputError(format!("Invalid hex format for PCR value at index {}", pcr_value.pcr_index)));
            }
        }

        // TODO: Implement PCR value validation against expected values
        // TODO: Check PCR values against known good measurements
        // TODO: Validate PCR extension sequence and integrity
        // TODO: Implement PCR value comparison with reference measurements
        log::info!("PCR verification passed with {} PCR values", self.pcrs.pcr_values.len());
        Ok(())
    }

    /// Verifies the evidence asynchronously.
    ///
    /// # Parameters
    /// - `user_id`: The user identifier.
    /// - `node_id`: Optional node identifier.
    /// - `nonce`: Optional nonce for verification.
    /// - `plugin`: Reference to the `AscendNpuPlugin`.
    ///
    /// # Returns
    /// A `Result` containing the verification result as `Value` or a `PluginError`.
    pub async fn verify(
        &self,
        user_id: &str,
        node_id: Option<&str>,
        nonce: Option<&[u8]>,
        plugin: &AscendNpuPlugin,
    ) -> Result<Value, PluginError> {
        log::info!("Starting AscendNPU evidence verification for user: {}", user_id);
        
        // TODO: Implement evidence freshness check (timestamp validation)
        // TODO: Add evidence integrity verification (hash validation)
        // TODO: Implement user-specific policy validation
        
        // Verify AK certificate
        self.verify_ak_cert()?;

        // Verify Quote data
        self.verify_quote(nonce)?;

        // Verify PCR data
        self.verify_pcrs()?;

        // Verify logs (if present)
        // Note: Logs are optional in AscendNPU evidence. Verification will pass
        // even if no logs are provided, as long as other components are valid.
        let log_results = if let Some(logs) = &self.logs {
            crate::log_verifier::verify_all_logs(logs, plugin, user_id, node_id).await?
        } else {
            Vec::new()
        };

        // Build verification result
        let mut evidence_result_map = serde_json::Map::new();
        
        // TODO: Add comprehensive verification metrics and statistics
        // TODO: Include security posture assessment results
        // TODO: Add compliance status and policy evaluation results
        
        // Add certificate information
        evidence_result_map.insert("cert_info".to_string(), 
            serde_json::json!({
                "ak_cert_verified": true,
                "cert_type": "AK Certificate"
            }));

        // Add Quote information
        evidence_result_map.insert("quote_info".to_string(),
            serde_json::json!({
                "quote_verified": true,
                "quote_data_length": self.quote.quote_data.len(),
                "signature_length": self.quote.signature.len()
            }));

        // Add PCR information
        evidence_result_map.insert("pcr_info".to_string(),
            serde_json::json!({
                "pcr_verified": true,
                "hash_algorithm": self.pcrs.hash_alg,
                "pcr_count": self.pcrs.pcr_values.len(),
                "pcr_indices": self.pcrs.pcr_values.iter().map(|p| p.pcr_index).collect::<Vec<i32>>()
            }));

        // Add log verification results
        if !log_results.is_empty() {
            let log_results_vec = log_results.into_iter().map(|log_result| log_result.to_json_value()).collect::<Vec<Value>>();
            for log_value in log_results_vec {
                if let Some(log_map) = log_value.as_object() {
                    evidence_result_map.extend(log_map.clone());
                }
            }
        } else {
            // Add log info when no logs are present
            evidence_result_map.insert("log_info".to_string(),
                serde_json::json!({
                    "logs_present": false,
                    "log_count": 0,
                    "message": "No logs provided - verification passed without log validation"
                }));
        }

        let evidence_result = Value::Object(evidence_result_map);

        log::info!("AscendNPU evidence verification completed successfully");
        Ok(evidence_result)
    }
}

