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

//! PCR values verifier, verify PCR values and replay values.
//! # Examples
//! See the `verify` method for an example of how to use the PcrValues struct.
use serde::{Serialize, Deserialize};
use openssl::hash::Hasher;
use plugin_manager::PluginError;
use crate::crypto_utils::CryptoVerifier;
use crate::quote::QuoteVerifier;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValueEntry {
    pub pcr_index: u32,
    pub pcr_value: String,
    #[serde(skip_serializing)]
    pub replay_value: Option<String>,
    #[serde(skip_serializing)]
    pub is_matched: Option<bool>,  // Verification result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValues {
    pub hash_alg: String,
    pub pcr_values: Vec<PcrValueEntry>, 
}

impl PcrValues {
    pub fn new() -> Self {
        Self {
            hash_alg: String::new(),
            pcr_values: vec![],
        }
    }

    /// Create a new PcrValues instance from JSON
    ///
    /// # Arguments
    /// * `json` - JSON representation of PCR values
    ///
    /// # Returns
    /// * `Result<Self, PluginError>` - PcrValues instance or error
    /// # Example
    /// ```
    /// use tpm_common_verifier::PcrValues;
    /// use serde_json::json;
    ///
    /// let json_value = json!({
    ///     "hash_alg": "sha256",
    ///     "pcr_values": [
    ///         {
    ///             "pcr_index": 0,
    ///             "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35"
    ///         },
    ///         {
    ///             "pcr_index": 1,
    ///             "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be"
    ///         }
    ///     ]
    /// });
    /// let pcr_values = PcrValues::from_json(&json_value).unwrap();
    /// ```
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the JSON is invalid or missing required fields.
    pub fn from_json(json: &serde_json::Value) -> Result<Self, PluginError> {
        if json.to_string().as_bytes().len() > 5 * 1024 * 1024 {
            return Err(PluginError::InputError("Log size exceeds 5MB limit".to_string()));
        }

        let bank: PcrValues = serde_json::from_value(json.clone())
            .map_err(|e| PluginError::InputError(
                format!("Failed to parse PCR values: {}", e)
            ))?;

        Ok(Self { hash_alg: bank.hash_alg, pcr_values: bank.pcr_values })
    }

    /// Get the PCR value for a specific index
    ///
    /// # Arguments
    /// 
    /// * `index` - PCR index to retrieve
    /// 
    /// # Returns
    /// 
    /// * `Option<&str>` - PCR value as a string, or `None` if not found
    pub fn get_pcr_value(&self, index: u32) -> Option<&str> {
        self.pcr_values.iter()
            .find(|entry| entry.pcr_index == index)
            .map(|entry| entry.pcr_value.as_str())
    }

    /// Get the replay value for a specific index
    ///
    /// # Arguments
    /// 
    /// * `index` - PCR index to retrieve
    /// 
    /// # Returns
    /// 
    /// * `Option<&str>` - Replay value as a string, or `None` if not found
    pub fn get_pcr_indices(&self) -> Vec<u32> {
        self.pcr_values.iter()
            .map(|entry| entry.pcr_index)
            .collect()
    }

    fn calculate_bank_digest(&self) -> Result<Vec<u8>, PluginError> {
        let digest_alg = CryptoVerifier::hash_str_to_message_digest(&self.hash_alg)
            .map_err(|e| PluginError::InputError(
                format!("Unsupported hash algorithm: {}, error: {}", self.hash_alg, e)
            ))?;

        let mut hasher = Hasher::new(digest_alg)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to create hasher: {}", e)
            ))?;

        let mut entries = self.pcr_values.clone();
        entries.sort_by_key(|entry| entry.pcr_index);

        for entry in entries {
            let binary = hex::decode(&entry.pcr_value)
                .map_err(|e| PluginError::InputError(
                    format!("Failed to parse PCR value: PCR{} = {}, error: {}", entry.pcr_index, entry.pcr_value, e)
                ))?;

            hasher.update(&binary)
                .map_err(|e| PluginError::InternalError(
                    format!("Failed to update hash: {}", e)
                ))?;
        }

        let digest = hasher.finish()
            .map_err(|e| PluginError::InternalError(
                format!("Failed to finalize hash calculation: {}", e)
            ))?;

        Ok(digest.to_vec())
    }

    /// Verify PCR values against a QuoteVerifier
    ///
    /// # Arguments
    /// * `quote_verifier` - QuoteVerifier instance
    ///
    /// # Returns
    /// * `Result<bool, PluginError>` - Verification result or error
    /// # Example
    /// ```ignore
    /// use tpm_common_verifier::{PcrValues, QuoteVerifier};
    ///
    /// let pcr_values = PcrValues::from_json(&json_value).unwrap();
    /// let quote_verifier = QuoteVerifier::new(&quote_bytes, &signature_bytes).unwrap();
    /// let result = pcr_values.verify(&quote_verifier).unwrap();
    /// ```
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the PCR values are invalid or missing required fields.
    pub fn verify(&self, quote_verifier: &QuoteVerifier) -> Result<bool, PluginError> {
        // Calculate PCR digest
        let calculated_digest = self.calculate_bank_digest()?;

        // Get Quote digest
        let quote_digest = quote_verifier.get_pcr_digest();

        if calculated_digest == quote_digest {
            Ok(true)
        } else {
            Err(PluginError::InputError("PCR digest mismatch".to_string()))
        }
    }

    /// Update the replay value for a specific PCR index
    ///
    /// # Arguments
    /// * `index` - PCR index to update
    /// * `value` - New replay value to set
    pub fn update_replay_value(&mut self, index: u32, value: String) {
        if let Some(entry) = self.pcr_values.iter_mut().find(|e| e.pcr_index == index) {
            entry.replay_value = Some(value);
        }
    }

    /// Get the PCR digest algorithm used by this PCR bank
    ///
    /// # Returns
    /// * `&str` - Hash algorithm name (e.g., "sha256", "sm3")
    pub fn get_pcr_digest_algorithm(&self) -> &str {
        &self.hash_alg
    }

    /// Get the PCR value for a specific PCR index
    ///
    /// # Arguments
    /// 
    /// * `index` - PCR index to retrieve
    /// 
    /// # Returns
    /// 
    /// * `Result<String, PluginError>` - PCR value as a string, or error if not found
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the PCR value is not found.
    pub fn get_pcr_digest(&self, index: u32) -> Result<String, PluginError> {
        self.pcr_values.iter()
            .find(|e| e.pcr_index == index)
            .map(|entry| entry.pcr_value.clone())
            .ok_or_else(|| PluginError::InputError("PCR value not found".to_string()))
    }

    /// Get the replay value for a specific PCR index
    ///
    /// # Arguments
    /// 
    /// * `index` - PCR index to retrieve
    /// 
    /// # Returns
    /// 
    /// * `Result<Option<String>, PluginError>` - Replay value as a string, or error if not found
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the replay value is not found.
    pub fn get_pcr_replay_value(&self, index: u32) -> Result<Option<String>, PluginError> {
        Ok(self.pcr_values
            .iter()
            .find(|e| e.pcr_index == index)
            .and_then(|entry| entry.replay_value.clone()))
    }

    /// Get the match status for a specific PCR index
    ///
    /// # Arguments
    /// 
    /// * `index` - PCR index to retrieve
    /// 
    /// # Returns
    /// 
    /// * `Result<Option<bool>, PluginError>` - Match status as a boolean, or error if not found
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the match status is not found.
    pub fn check_is_matched(&mut self) -> Result<bool, PluginError> {
        let mut all_matched = true;

        // Iterate through all PCR entries to set their is_matched status
        for entry in &mut self.pcr_values {
            // Check if matched: replay_value exists and equals pcr_value
            let matched = entry.replay_value
                .as_ref()
                .map_or(false, |replay| *replay == entry.pcr_value);

            // Set match status
            entry.is_matched = Some(matched);

            // Update overall match status while continuing to process all entries
            if !matched {
                all_matched = false;
            }
        }

        // Return overall match result
        Ok(all_matched)
    }

    /// Calculates the final PCR value by extending log entries according to TPM's PCR extension logic
    /// 
    /// # Arguments
    /// 
    /// * `algorithm` - Hash algorithm name (e.g., "sha256", "sm3")
    /// * `initial_value` - Initial PCR value
    /// * `log_values` - Vector of log values to extend
    /// 
    /// # Returns
    /// 
    /// * `Result<String, PluginError>` - Final PCR value as a string, or error if calculation fails
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the input values are invalid or missing required fields.
    pub fn replay(
        algorithm: &str,
        initial_value: &str,
        log_values: &Vec<String>
    ) -> Result<String, PluginError> {
        Self::replay_internal(algorithm, initial_value, log_values, None)
    }

    /// Calculates the final PCR value by extending log entries according to TPM's PCR extension logic
    /// 
    /// # Arguments
    /// 
    /// * `algorithm` - Hash algorithm name (e.g., "sha256", "sm3")
    /// * `initial_value` - Initial PCR value
    /// * `target_value` - Target PCR value
    /// * `log_values` - Vector of log values to extend
    /// 
    /// # Returns
    /// 
    /// * `Result<String, PluginError>` - Final PCR value as a string, or error if calculation fails
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the input values are invalid or missing required fields.
    pub fn replay_with_target(
        algorithm: &str,
        initial_value: &str,
        target_value: &str,
        log_values: &Vec<String>
    ) -> Result<String, PluginError> {
        let target_bytes = hex::decode(target_value)
            .map_err(|e| PluginError::InputError(format!("Failed to decode target value: {}", e)))?;
        
        Self::replay_internal(algorithm, initial_value, log_values, Some(&target_bytes))
    }
    
    /// Internal helper function that implements the common PCR replay logic
    fn replay_internal(
        algorithm: &str,
        initial_value: &str,
        log_values: &Vec<String>,
        target_value: Option<&[u8]>
    ) -> Result<String, PluginError> {
        let digest_alg = CryptoVerifier::hash_str_to_message_digest(algorithm)?;

        let mut current_value = hex::decode(initial_value)
            .map_err(|e| PluginError::InputError(format!("Failed to decode initial value: {}", e)))?;
        
        for log_value in log_values {
            let log_bytes = hex::decode(log_value)
                .map_err(|e| PluginError::InputError(format!("Failed to decode log value: {}", e)))?;
            
            let mut hasher = openssl::hash::Hasher::new(digest_alg)
                .map_err(|e| PluginError::InternalError(format!("Failed to create hasher: {}", e)))?;

            hasher.update(&current_value)
                .map_err(|e| PluginError::InternalError(format!("Failed to update hash with current value: {}", e)))?;

            hasher.update(&log_bytes)
                .map_err(|e| PluginError::InternalError(format!("Failed to update hash with log value: {}", e)))?;

            current_value = hasher.finish()
                .map_err(|e| PluginError::InternalError(format!("Failed to finalize hash: {}", e)))?
                .to_vec();
            
            // Early return if we've reached the target value (only if target_value is Some)
            if let Some(target) = target_value {
                if current_value == target {
                    break;
                }
            }
        }

        Ok(hex::encode(current_value))
    }
}

/// Valid PCR index range (0-23)
const PCR_INDEX_MIN: i32 = 0;
const PCR_INDEX_MAX: i32 = 23;

/// Validates if the given PCR index is within valid range
fn is_valid_pcr_index(index: u32) -> bool {
    index >= PCR_INDEX_MIN as u32 && index <= PCR_INDEX_MAX as u32
}

/// Validates if the given string is valid hexadecimal format
fn is_valid_hex_string(hex_str: &str) -> bool {
    hex_str.len() % 2 == 0 && hex_str.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validates PCR values for format correctness and basic constraints
/// 
/// This function performs validity checks only:
/// - Ensures PCR values are not empty
/// - Checks for duplicate PCR indices
/// - Validates PCR index range (0-23)
/// - Verifies hexadecimal format
/// 
/// It does NOT compare against reference values since `AscendNPU` PCRs have no baseline.
pub fn validate_pcr_values(pcr_values: &[PcrValueEntry]) -> Result<(), PluginError> {
    if pcr_values.is_empty() {
        return Err(PluginError::InputError("PCR values cannot be empty".to_string()));
    }

    // Check for duplicate PCR indices
    let mut seen_indices = HashSet::new();
    for pcr_value in pcr_values {
        if !seen_indices.insert(pcr_value.pcr_index) {
            return Err(PluginError::InputError(format!(
                "Duplicate PCR index found: {}",
                pcr_value.pcr_index
            )));
        }
    }

    // Validate each PCR value
    for (idx, pcr_value) in pcr_values.iter().enumerate() {
        // Validate PCR index
        if !is_valid_pcr_index(pcr_value.pcr_index) {
            return Err(PluginError::InputError(format!(
                "Invalid PCR index at position {}: {}. Valid range: {}-{}",
                idx, pcr_value.pcr_index, PCR_INDEX_MIN, PCR_INDEX_MAX
            )));
        }

        // Validate hexadecimal format
        if !is_valid_hex_string(&pcr_value.pcr_value) {
            return Err(PluginError::InputError(format!(
                "Invalid hex format for PCR value at position {} (index {}): '{}'",
                idx, pcr_value.pcr_index, pcr_value.pcr_value
            )));
        }
    }

    Ok(())
}
