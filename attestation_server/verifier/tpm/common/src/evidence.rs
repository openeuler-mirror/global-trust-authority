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

//! This module provides the evidence struct and its verification logic.
//!
//! # Overview
//! The Evidence module is a core component of the attestation verification system.
//! It defines structures and traits for handling, validating, and processing 
//! restful attestation evidence from devices.
//!
//! # Key Components
//!
//! ## Evidence
//! The main structure representing attestation evidence from a device, including:
//! - TPM Quote data and signature
//! - PCR (Platform Configuration Register) values
//! - Event logs
//! - Attestation Key certificate
//!
//! ## GenerateEvidence Trait
//! An interface that plugins must implement to generate verification results
//! based on the evidence data.
//!
//! ## Verification Process
//! The `verify` method implements a complete verification workflow:
//! 1. Certificate chain validation
//! 2. Quote signature verification
//! 3. PCR value validation
//! 4. Evidence generation through the plugin
//!
//! # Usage
//! This module is used by verification plugins to process and validate
//! attestation evidence according to their specific verification logic.
//!
//! # Examples
//! See the `verify` method for an example of how to use the Evidence struct.

use serde_json::Value;
use serde::{Serialize, Deserialize};
use openssl::x509::X509;
use plugin_manager::{PluginError, ServiceHostFunctions};
use crate::pcr::PcrValues;
use crate::quote::QuoteVerifier;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use async_trait::async_trait;

/// Generate evidence trait.
/// Plugins implement this trait to generate evidence.
#[async_trait]
pub trait GenerateEvidence: Send + Sync {
    async fn generate_evidence(
        &self,
        user_id: &str,
        logs: Option<&Vec<Logs>>,
        pcr_values: &mut PcrValues
    ) -> Result<Value, PluginError>;

    fn get_host_functions(&self) -> &ServiceHostFunctions;

    fn get_plugin_type(&self) -> &str;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AkCertData {
    pub cert_type: String,
    pub cert_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Logs {
    pub log_type: String,
    pub log_data: String,
}

/// Evidence struct.
///
/// This struct represents the complete attestation evidence from a device, including:
/// - TPM Quote data and signature
/// - PCR (Platform Configuration Register) values
/// - Event logs or other log data
/// - Attestation Key certificate
#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub marshalled_quote: Vec<u8>,
    pub quote: QuoteVerifier,
    pub pcrs: PcrValues,
    pub logs: Option<Vec<Logs>>,
    pub ak_certs: Vec<AkCertData>,
}

impl Evidence {
    /// Create a new Evidence instance from a JSON value.
    ///
    /// # Examples
    /// ```ignore
    /// // Note: This example is for illustration only and not compiled as part of documentation tests
    /// use serde_json::json;
    /// use tpm_common_verifier::evidence::Evidence;
    ///
    /// // JSON format for evidence input
    /// let evidence_json = json!({
    ///     "quote": {
    ///         "quote_data": "base64_encoded_quote_data",
    ///         "signature": "base64_encoded_signature"
    ///     },
    ///     "pcrs": {
    ///         "hash_alg": "sha256",
    ///         "pcr_values": [
    ///             {
    ///                 "pcr_index": 0,
    ///                 "pcr_value": "0123456789abcdef0123456789abcdef01234567"
    ///             }
    ///         ]
    ///     },
    ///     "logs": [{
    ///         "log_type": "tpm_boot",
    ///         "log_data": "log data string"
    ///     }],
    ///     "ak_certs": [
    ///         {
    ///             "cert_type": "iak",
    ///             "cert_data": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
    ///     }]
    /// });
    ///
    /// // In actual code, Evidence would be properly imported
    /// let evidence = Evidence::from_json_value(&evidence_json).unwrap();
    /// ```
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the JSON value is missing required fields or has invalid data.
    pub fn from_json_value(json_value: &Value) -> Result<Self, PluginError> {
        let required_fields = &["quote", "pcrs", "ak_certs"];
        Self::validate_json_fields(json_value, required_fields)
            .map_err(|e| PluginError::InputError(e))?;

        let quote = &json_value["quote"];
        let quote_base64 = quote["quote_data"].as_str()
            .ok_or_else(|| PluginError::InputError("Quote data must be a string".to_string()))?;
        let signature_base64 = quote["signature"].as_str()
            .ok_or_else(|| PluginError::InputError("Signature must be a string".to_string()))?;

        let quote_value = BASE64.decode(quote_base64)
            .map_err(|e| PluginError::InputError(format!("Failed to decode Quote data: {}", e)))?;
        let signature_value = BASE64.decode(signature_base64)
            .map_err(|e| PluginError::InputError(format!("Failed to decode signature data: {}", e)))?;

        let quote_verifier = QuoteVerifier::new(&quote_value, &signature_value)?;

        let pcr_values = if let Some(pcrs) = json_value.get("pcrs") {
            PcrValues::from_json(pcrs)?
        } else {
            return Err(PluginError::InputError("Missing PCR values".to_string()));
        };

        let logs: Option<Vec<Logs>> = if let Some(logs) = json_value.get("logs") {
            serde_json::from_value(logs.clone())
                .map_err(|e| PluginError::InputError(format!("Failed to parse log: {}", e)))?
        } else {
            None
        };

        let ak_certs_array = json_value["ak_certs"].as_array()
            .ok_or_else(|| PluginError::InternalError("AK certs array not found or invalid".to_string()))?;

        let mut ak_certs = Vec::new();
        for (idx, ak_cert_obj) in ak_certs_array.iter().enumerate() {
            let cert_type: String = ak_cert_obj
                .get("cert_type")
                .and_then(|v| v.as_str())
                .map(String::from)
                .ok_or_else(|| PluginError::InternalError(format!("AK cert type not found or invalid at index {}", idx)))?;

            let cert_data: String = ak_cert_obj
                .get("cert_data")
                .and_then(|v| v.as_str())
                .map(String::from)
                .ok_or_else(|| PluginError::InternalError(format!("AK cert data not found or invalid at index {}", idx)))?;

            let valid_cert_type = &["aik", "iak", "lak"];
            if !valid_cert_type.contains(&cert_type.as_str()) {
                return Err(PluginError::InputError(format!("Invalid ak cert type at index {}: {}", idx, cert_type)));
            }

            ak_certs.push(AkCertData {
                cert_type,
                cert_data,
            });
        }

        if ak_certs.is_empty() {
            return Err(PluginError::InternalError("No AK certificates found".to_string()));
        }

        // Check if LAK certificate exists, then IAK certificate must also exist
        if ak_certs.iter().any(|cert| cert.cert_type == "lak") {
            if !ak_certs.iter().any(|cert| cert.cert_type == "iak") {
                return Err(PluginError::InputError("If LAK certificate exists, IAK certificate must also exist".to_string()));
            }
        }
        Ok(Evidence {
            marshalled_quote: quote_value,
            quote: quote_verifier,
            pcrs: pcr_values,
            logs,
            ak_certs,
        })
    }

    fn validate_json_fields(json: &Value, required_fields: &[&str]) -> Result<(), String> {
        let missing_fields: Vec<&str> = required_fields
            .iter()
            .filter(|&field| json.get(*field).is_none())
            .cloned()
            .collect();

        if missing_fields.is_empty() {
            Ok(())
        } else {
            Err(PluginError::InputError(format!("Missing required fields: {}", missing_fields.join(", "))).to_string())
        }
    }

    fn parse_ak_certificate(&self, cert_data: &str) -> Result<X509, PluginError> {
        // 1. Try standard PEM format
        if let Ok(cert) = X509::from_pem(cert_data.as_bytes()) {
            return Ok(cert);
        }

        // 2. Try adding PEM header and footer
        let pem_cert = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", cert_data);
        if let Ok(cert) = X509::from_pem(pem_cert.as_bytes()) {
            return Ok(cert);
        }

        // 3. Try base64 decoding to DER format
        match BASE64.decode(cert_data.as_bytes()) {
            Ok(der_data) => {
                match X509::from_der(&der_data) {
                    Ok(cert) => Ok(cert),
                    Err(e) => Err(PluginError::InputError(
                        format!("Failed to parse certificate from DER format: {}", e)
                    ))
                }
            },
            Err(e) => Err(PluginError::InputError(
                format!("Failed to parse certificate: not a valid PEM or base64 format: {}", e)
            ))
        }
    }

    /// Verifies the complete attestation evidence by performing a series of validation steps.
    ///
    /// This method performs the following verification steps:
    /// 1. Validates the attestation key certificate chain
    /// 2. Verifies that the node_id matches the certificate's subject
    /// 3. Validates the TPM quote signature using the public key from the certificate
    /// 4. Verifies PCR values against the quote's digest
    /// 5. Generates evidence verification results using the provided generator
    ///
    /// # Arguments
    ///
    /// * `user_id` - The identifier of the user requesting verification, used to validate the certificate chain
    /// * `node_id` - Optional node identifier that should match the certificate's common name
    /// * `nonce` - Optional nonce value to verify freshness of the quote
    /// * `generator` - Implementation of the `GenerateEvidence` trait to produce verification results.
    ///                 Plugins implement this trait to generate evidence.
    /// * `validate_cert_chain` - Function for validating the certificate chain. Certificate manager
    ///                           implements this function. Attestation module registers this function.
    ///
    /// # Returns
    ///
    /// * `Result<Value, PluginError>` - Returns a JSON Value containing the parsed evidence and
    ///                                  verification results on success, or a PluginError on failure.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Note: This example is for illustration only and not compiled as part of documentation tests
    /// use tpm_common_verifier::{
    ///     evidence::{Evidence, GenerateEvidence, LogResult, EvidenceResult},
    ///     pcr::PcrValues
    /// };
    /// use serde_json::{json, Value};
    /// use plugin_manager::PluginError;
    ///
    /// // Implement the GenerateEvidence trait
    /// struct MyPlugin;
    ///
    /// impl GenerateEvidence for MyPlugin {
    ///     fn generate_evidence(&self, user_id: &str, logs: &Vec<Logs>, pcr_values: &mut PcrValues)
    ///         -> Result<Value, PluginError> {
    ///         // Create sample verification results
    ///         let logs = vec![
    ///             LogResult {
    ///                 log_type: "tpm_boot".to_string(),
    ///                 log_data: serde_json::json!([
    ///                     {
    ///                         "event_number": 0,
    ///                         "pcr_index": 1,
    ///                         "event_type": "EV_NO_ACTION",
    ///                         "digest": "0123456789abcdef0123456789abcdef01234567",
    ///                         "event": {}
    ///                     },
    ///                     {
    ///                         "event_number": 1,
    ///                         "pcr_index": 2,
    ///                         "event_type": "EV_SEPARATOR",
    ///                         "digest": "9876543210fedcba9876543210fedcba98765432",
    ///                         "event": {}
    ///                     }
    ///                 ])
    ///             }
    ///         ];
    ///
    ///         // Create and return evidence result
    ///         let evidence_result = EvidenceResult::new(true, logs, pcr_values.clone());
    ///         let result = evidence_result.to_json_value();
    ///         Ok(result)
    ///     }
    /// }
    ///
    /// // Create validator function
    /// let validator = |cert_type: &str, user_id: &str, cert_data: &[u8]| -> bool {
    ///     // In a real implementation, validate certificate chain
    ///     !cert_data.is_empty()
    /// };
    ///
    /// // Verify evidence
    /// let evidence = Evidence::from_json_value(&json!({/* evidence data */})).unwrap();
    /// let verifier = MyPlugin;
    /// let result = evidence.verify(
    ///     "test_user",
    ///     Some("device_001".to_string()),
    ///     None,
    ///     &verifier
    /// );
    /// ```
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the certificate chain validation fails or the node_id does not match the certificate's common name.
    pub async fn verify(
        &mut self,
        user_id: &str,
        _node_id: Option<&str>,
        nonce: Option<&[u8]>,
        generator: &dyn GenerateEvidence,
    ) -> Result<Value, PluginError> {
        for ak_cert in &self.ak_certs {
            let validate_cert_chain = &generator.get_host_functions().validate_cert_chain;
            // Validate certificate chain
            if !(validate_cert_chain)(generator.get_plugin_type(), user_id, ak_cert.cert_data.as_bytes()).await {
                return Err(PluginError::InputError("Certificate chain validation failed".to_string()));
            }
        }

        let ak_cert: &AkCertData = if self.ak_certs.len() == 1 {
            &self.ak_certs[0]
        } else {
            self.ak_certs.iter()
                .find(|cert| cert.cert_type == "lak")
                .ok_or_else(|| PluginError::InputError("No LAK certificate found".to_string()))?
        };

        // Parse AK certificate
        let ak_cert = self.parse_ak_certificate(ak_cert.cert_data.as_str())?;

        let public_ak = ak_cert.public_key()
            .map_err(|e| PluginError::InputError(format!("Failed to extract public key from certificate: {}", e)))?;
        // Verify quote and signature
        self.quote.verify(&self.marshalled_quote, &public_ak, nonce)?;

        // Verify PCR values
        self.pcrs.verify(&self.quote)?;

        let evidence = generator.generate_evidence(user_id, self.logs.as_ref(), &mut self.pcrs).await?;

        Ok(evidence)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogResult {
    pub log_status: String,
    pub ref_value_match_status: String,
    pub log_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_data: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceResult {
    pub log_result: Vec<LogResult>,
    pub pcr_values: PcrValues,
}

impl EvidenceResult {
    /// Create a new EvidenceResult instance. Provide this struct to the plugin manager to generate evidence result.
    ///
    /// # Arguments
    /// * `log_result` - A vector of LogResult instances.
    /// * `pcr_values` - A PcrValues instance.
    ///
    /// # Returns
    /// * `Self` - A new EvidenceResult instance.
    pub fn new(
        log_result: Vec<LogResult>,
        pcr_values: PcrValues
    ) -> Self {
        Self {
            log_result,
            pcr_values
        }
    }

    /// Convert the EvidenceResult instance to a JSON value.
    ///
    /// # Returns
    /// * `Value` - A JSON value representing the EvidenceResult.
    pub fn to_json_value(&self) -> Value {
        let mut log_results = Vec::new();
        for log in &self.log_result {
            let mut log_entry = serde_json::Map::new();
        
            // Always include these fields
            log_entry.insert("log_status".to_string(), Value::String(log.log_status.clone()));
            log_entry.insert("ref_value_match_status".to_string(), Value::String(log.ref_value_match_status.clone()));
            log_entry.insert("log_type".to_string(), Value::String(log.log_type.clone()));
            
            
            // Only include log_data if it's Some
            if let Some(log_data) = &log.log_data {
                log_entry.insert("log_data".to_string(), log_data.clone());
            }
            
            log_results.push(Value::Object(log_entry));
        }

        let pcrs_json = serde_json::json!({
            "hash_alg": self.pcr_values.hash_alg,
            "pcr_values": self.pcr_values.pcr_values
        });

        serde_json::json!({
            "evidence": {
                "logs": log_results,
                "pcrs": pcrs_json
            }
        })
    }
}
