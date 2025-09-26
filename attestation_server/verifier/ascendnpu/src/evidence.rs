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
use openssl::pkey::PKey;
use openssl::pkey::Public;
use plugin_manager::PluginError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering::{Greater, Less};

use crate::verifier::AscendNpuPlugin;
use tpm_common_verifier::{
    QuoteVerifier, PcrValues, PcrValueEntry
};
use tpm_common_verifier::pcr::validate_pcr_values;

/// Supported hash algorithms for PCR verification (SHA256 only)
const SUPPORTED_HASH_ALGORITHMS: &[&str] = &["sha256"];

/// Default hash algorithm
const DEFAULT_HASH_ALGORITHM: &str = "sha256";

/// Validates if the given hash algorithm is supported
fn is_supported_hash_algorithm(algorithm: &str) -> bool {
    SUPPORTED_HASH_ALGORITHMS.contains(&algorithm)
}



// Use TpmsAttest from tpm_common_verifier instead of custom TpmQuoteAttest

// Use TpmsClockInfo from tpm_common_verifier instead of custom TpmClockInfo

// Use TpmsQuoteInfo and TpmsPcrSelection from tpm_common_verifier instead of custom structures

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub log_type: String,
    pub log_data: String,
}

/// `AscendNPU` Quote structure - now using `tpm_common_verifier` `QuoteVerifier`
pub type AscendNpuQuote = QuoteVerifier;

/// `AscendNPU` PCRs structure - now using `tpm_common_verifier` `PcrValues`
pub type AscendNpuPcrs = PcrValues;

/// `AscendNPU` PCR value structure - now using `tpm_common_verifier` `PcrValueEntry`
pub type AscendNpuPcrValue = PcrValueEntry;

/// Represents the `AscendNPU` evidence structure.
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


impl AscendNpuEvidence {
    /// Creates an `AscendNpuEvidence` instance from a JSON value.
    ///
    /// # Parameters
    /// - `json_value`: The JSON value to parse.
    ///
    /// # Errors
    /// 
    /// This function will return an error if:
    /// - Required fields are missing
    /// - Field types are incorrect
    /// - JSON parsing fails
    /// - Certificate parsing fails
    /// - Quote data parsing fails
    /// - PCR data parsing fails
    /// - Log data parsing fails
    ///
    /// # Returns
    /// A `Result` containing the `AscendNpuEvidence` or a `PluginError`.
    pub fn from_json_value(json_value: &Value) -> Result<Self, PluginError> {
        Self::validate_required_fields(json_value)?;
        
        let ak_cert = Self::parse_ak_cert(json_value)?;
        let quote = Self::parse_quote(json_value)?;
        let pcrs = Self::parse_pcrs(json_value)?;
        let logs = Self::parse_logs(json_value)?;

        Ok(AscendNpuEvidence { ak_cert, quote, pcrs, logs })
    }

    /// Validates that all required fields are present in the JSON value.
    fn validate_required_fields(json_value: &Value) -> Result<(), PluginError> {
        let required_fields = &["ak_cert", "quote", "pcrs"];
        for field in required_fields {
            if json_value.get(*field).is_none() {
                return Err(PluginError::InputError(format!("Missing required field: {}", field)));
            }
        }
        Ok(())
    }

    /// Parses the AK certificate from the JSON value.
    fn parse_ak_cert(json_value: &Value) -> Result<String, PluginError> {
        json_value["ak_cert"]
            .as_str()
            .ok_or(PluginError::InputError("ak_cert must be a string".to_string()))
            .map(|s| s.to_string())
    }

    /// Parses the Quote data from the JSON value.
    fn parse_quote(json_value: &Value) -> Result<QuoteVerifier, PluginError> {
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

        QuoteVerifier::from_base64(&quote_data, &signature)
    }

    /// Parses the PCR data from the JSON value.
    fn parse_pcrs(json_value: &Value) -> Result<PcrValues, PluginError> {
        let pcrs_obj = json_value.get("pcrs")
            .ok_or(PluginError::InputError("pcrs field is required".to_string()))?;

        let hash_alg = pcrs_obj.get("hash_alg")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_HASH_ALGORITHM)
            .to_string();

        let pcr_values_array = pcrs_obj.get("pcr_values")
            .and_then(|v| v.as_array())
            .ok_or(PluginError::InputError("pcrs.pcr_values must be an array".to_string()))?;

        let pcr_values = Self::parse_pcr_values_array(pcr_values_array)?;

        Ok(PcrValues {
            hash_alg,
            pcr_values,
        })
    }

    /// Parses the PCR values array from the JSON array.
    fn parse_pcr_values_array(pcr_values_array: &[Value]) -> Result<Vec<PcrValueEntry>, PluginError> {
        let mut pcr_values = Vec::new();
        for (idx, pcr_value_obj) in pcr_values_array.iter().enumerate() {
            let pcr_index = pcr_value_obj.get("pcr_index")
                .and_then(|v| v.as_i64())
                .ok_or(PluginError::InputError(format!("pcr_values[{}].pcr_index must be an integer", idx)))? as u32;

            let pcr_value = pcr_value_obj.get("pcr_value")
                .and_then(|v| v.as_str())
                .ok_or(PluginError::InputError(format!("pcr_values[{}].pcr_value must be a string", idx)))?
                .to_string();

            pcr_values.push(PcrValueEntry {
                pcr_index,
                pcr_value,
                replay_value: None,
                is_matched: None,
            });
        }
        Ok(pcr_values)
    }

    /// Parses the log data from the JSON value (optional field).
    fn parse_logs(json_value: &Value) -> Result<Option<Vec<Log>>, PluginError> {
        if let Some(log_array) = json_value.get("logs") {
            if !log_array.is_array() {
                return Err(PluginError::InputError("logs must be an array".to_string()));
            }
            let parsed_logs = Self::parse_logs_array(log_array.as_array().unwrap())?;
            Ok(Some(parsed_logs))
        } else {
            Ok(None)
        }
    }

    /// Parses the logs array from the JSON array.
    fn parse_logs_array(log_array: &[Value]) -> Result<Vec<Log>, PluginError> {
        let mut parsed_logs = Vec::new();
        for log_value in log_array {
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
        Ok(parsed_logs)
    }

    /// Verify AK certificate
    async fn verify_ak_cert(&self, plugin: &AscendNpuPlugin, user_id: &str) -> Result<(), PluginError> {
        let cert_bytes = general_purpose::STANDARD.decode(&self.ak_cert)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 AK certificate: {}", e)))?;

        let cert = X509::from_der(&cert_bytes)
            .map_err(|e| PluginError::InputError(format!("Failed to parse AK certificate: {}", e)))?;

        // Check certificate validity period
        Self::check_cert_validity(&cert, "AK")?;

        // Validate certificate chain using host functions
        let validate_cert_chain = &plugin.get_host_functions().validate_cert_chain;
        if !(validate_cert_chain)(plugin.get_plugin_type(), user_id, &cert_bytes).await {
            return Err(PluginError::InputError("Certificate chain validation failed".to_string()));
        }

        Ok(())
    }

    /// Check certificate validity period
    fn check_cert_validity(cert: &X509, cert_type: &str) -> Result<(), PluginError> {
        let now = Asn1Time::days_from_now(0)
            .map_err(|e| PluginError::InputError(format!("Failed to get current time: {}", e)))?;

        // Check if certificate is not yet valid (current time < not_before)
        if now.compare(cert.not_before()).map_err(|e| PluginError::InputError(e.to_string()))? == Less {
            return Err(PluginError::InputError(format!("{} certificate is not yet valid", cert_type)));
        }

        // Check if certificate is expired (current time > not_after)
        if now.compare(cert.not_after()).map_err(|e| PluginError::InputError(e.to_string()))? == Greater {
            return Err(PluginError::InputError(format!("{} certificate is expired", cert_type)));
        }

        Ok(())
    }

    /// Verify Quote data and PCR values using `tpm_common_verifier`
    fn verify_quote_and_pcrs(&self, nonce: Option<&[u8]>) -> Result<(), PluginError> {
        log::info!("Starting Quote and PCR verification");
        
        // Use the QuoteVerifier instance directly
        let quote_verifier = &self.quote;
        
        // Get AK certificate public key
        let public_key = self.get_ak_public_key()?;
        
        // Get quote data for verification
        let quote_data = self.quote.get_quote_data_bytes()?;
        

        // Verify quote
        quote_verifier.verify(&quote_data, &public_key, nonce)
            .map_err(|e| PluginError::InputError(format!("Quote verification failed: {}", e)))?;
        
        // Verify PCR data validity and against Quote
        self.verify_pcrs(&quote_verifier)?;
       
        Ok(())
    }

    /// Get AK certificate public key
    fn get_ak_public_key(&self) -> Result<PKey<Public>, PluginError> {
        // Decode AK certificate
        let cert_bytes = general_purpose::STANDARD.decode(&self.ak_cert)
            .map_err(|e| PluginError::InputError(format!("Failed to decode AK certificate: {}", e)))?;
        
        let cert = X509::from_der(&cert_bytes)
            .map_err(|e| PluginError::InputError(format!("Failed to parse AK certificate: {}", e)))?;
        
        // Get public key from certificate
        let public_key = cert.public_key()
            .map_err(|e| PluginError::InputError(format!("Failed to extract public key: {}", e)))?;
        
        Ok(public_key)
    }



    /// Verify PCR data validity
    /// 
    /// This function validates PCR values for format correctness and basic constraints.
    /// Verify PCR values using `tpm_common_verifier`
    fn verify_pcrs(&self, quote_verifier: &QuoteVerifier) -> Result<(), PluginError> {
        
        // Verify hash algorithm
        if !is_supported_hash_algorithm(&self.pcrs.hash_alg) {
            let supported_algs = SUPPORTED_HASH_ALGORITHMS.join(", ");
            return Err(PluginError::InputError(format!(
                "Unsupported hash algorithm: '{}'. Supported algorithms: {}",
                self.pcrs.hash_alg, supported_algs
            )));
        }

        // Validate PCR values using comprehensive validation
        validate_pcr_values(&self.pcrs.pcr_values)?;

        // Verify PCR values against Quote
        // This ensures PCR values match those in the Quote and haven't been tampered with
        self.verify_pcrs_against_quote(quote_verifier)?;
       
        Ok(())
    }

    /// Verify PCR values against Quote using `tpm_common_verifier`
    fn verify_pcrs_against_quote(&self, quote_verifier: &QuoteVerifier) -> Result<(), PluginError> {
        log::info!("Starting PCR verification against Quote");
        
        // Convert AscendNPU PCR data to PcrValues format
        let pcr_values = self.convert_to_pcr_values()?;
        
        // Use tpm_common_verifier to verify PCR values against Quote
        pcr_values.verify(quote_verifier)
            .map_err(|e| PluginError::InputError(format!("PCR verification failed: {}", e)))?;
        
        Ok(())
    }

    /// Convert `AscendNPU` PCR data to `tpm_common_verifier` `PcrValues` format
    /// Since `AscendNpuPcrs` is now a type alias for `PcrValues`, we can return it directly
    fn convert_to_pcr_values(&self) -> Result<PcrValues, PluginError> {
        Ok(self.pcrs.clone())
    }

    /// Verifies the evidence asynchronously.
    ///
    /// # Parameters
    /// - `user_id`: The user identifier.
    /// - `node_id`: Optional node identifier.
    /// - `nonce`: Optional nonce for verification.
    /// - `plugin`: Reference to the `AscendNpuPlugin`.
    ///
    /// # Errors
    /// 
    /// This function will return an error if:
    /// - AK certificate verification fails
    /// - Quote verification fails
    /// - PCR verification fails
    /// - Log verification fails
    /// - JSON serialization fails
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
        
        // Verify AK certificate
        self.verify_ak_cert(plugin, user_id).await?;

        // Verify Quote data
        self.verify_quote_and_pcrs(nonce)?;

        // Verify logs (if present)
        // Note: Logs are optional in AscendNPU evidence. Verification will pass
        // even if no logs are provided, as long as other components are valid.
        let log_results = if let Some(logs) = &self.logs {
            crate::log_verifier::verify_all_logs(logs, plugin, user_id, node_id, &self.pcrs).await?
        } else {
            Vec::new()
        };

        // Build verification result
        let mut evidence_result_map = serde_json::Map::new();
        
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
            }));

        // Add PCR information
        evidence_result_map.insert("pcr_info".to_string(),
            serde_json::json!({
                "pcr_verified": true,
                "hash_algorithm": self.pcrs.hash_alg,
                "pcr_count": self.pcrs.pcr_values.len(),
                "pcr_indices": self.pcrs.pcr_values.iter().map(|p| p.pcr_index).collect::<Vec<u32>>()
            }));

        // Add log verification results
        if !log_results.is_empty() {
            // Group logs by type and create structured results
            let mut boot_logs = Vec::new();
            let mut runtime_logs = Vec::new();
            let mut other_logs = Vec::new();
            
            for log_result in log_results {
                match log_result.log_type.as_str() {
                    "boot_measurement" => boot_logs.push(log_result.to_json_value()),
                    "runtime_measurement" => runtime_logs.push(log_result.to_json_value()),
                    _ => other_logs.push(log_result.to_json_value()),
                }
            }
            
            // Add structured log results
            if !boot_logs.is_empty() {
                evidence_result_map.insert("boot_logs".to_string(), Value::Array(boot_logs));
            }
            if !runtime_logs.is_empty() {
                evidence_result_map.insert("runtime_logs".to_string(), Value::Array(runtime_logs));
            }
            if !other_logs.is_empty() {
                evidence_result_map.insert("other_logs".to_string(), Value::Array(other_logs));
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

        Ok(evidence_result)
    }
}

