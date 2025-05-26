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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValueEntry {
    pub pcr_index: u32,
    pub pcr_value: String,
    pub replay_value: Option<String>,
    pub is_matched: Option<bool>,  // Verification result
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct PcrBank {
//     pub hash_alg: String,
//     pub pcr_values: Vec<PcrValueEntry>, 
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValues {
    // #[serde(rename = "pcrs")]
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
    pub fn from_json(json: &serde_json::Value) -> Result<Self, PluginError> {
        let bank: PcrValues = serde_json::from_value(json.clone())
            .map_err(|e| PluginError::InputError(
                format!("Failed to parse PCR values: {}", e)
            ))?;

        Ok(Self { hash_alg: bank.hash_alg, pcr_values: bank.pcr_values })
    }

    pub fn get_pcr_value(&self, index: u32) -> Option<&str> {
        self.pcr_values.iter()
            .find(|entry| entry.pcr_index == index)
            .map(|entry| entry.pcr_value.as_str())
    }

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
    pub fn verify(&self, quote_verifier: &QuoteVerifier) -> Result<bool, PluginError> {
        // Check if the hash algorithm used for verification is consistent
        let quote_alg = quote_verifier.get_hash_algorithm().to_string();

        if self.hash_alg.to_lowercase() != quote_alg.to_lowercase() {
            return Err(PluginError::InputError(
                format!("PCR value algorithm {} does not match Quote algorithm {}", self.hash_alg, quote_alg)
            ));
        }

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

    fn update_pcr_entry<F>(&mut self, index: u32, updater: F)
        where F: FnOnce(&mut PcrValueEntry)
    {
        if let Some(entry) = self.pcr_values.iter_mut().find(|e| e.pcr_index == index) {
            updater(entry);
        }
    }

    pub fn update_replay_value(&mut self, index: u32, value: String) {
        self.update_pcr_entry(index, |entry| entry.replay_value = Some(value));
    }

    pub fn update_is_matched(&mut self, index: u32, value: bool) {
        self.update_pcr_entry(index, |entry| entry.is_matched = Some(value));
    }

    pub fn get_pcr_digest_algorithm(&self) -> String {
        self.hash_alg.clone()
    }

    pub fn get_pcr_digest(&self, index: u32) -> Result<String, PluginError> {
        self.pcr_values.iter()
            .find(|e| e.pcr_index == index)
            .map(|entry| entry.pcr_value.clone())
            .ok_or_else(|| PluginError::InputError("PCR value not found".to_string()))
    }

    pub fn get_pcr_replay_value(&self, index: u32) -> Result<Option<String>, PluginError> {
        Ok(self.pcr_values
            .iter()
            .find(|e| e.pcr_index == index)
            .and_then(|entry| entry.replay_value.clone()))
    }

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
    pub fn replay(
        algorithm: &str,
        initial_value: &str,
        log_values: &Vec<String>
    ) -> Result<String, PluginError> {
        let digest_alg = CryptoVerifier::hash_str_to_message_digest(algorithm)?;

        let mut current_value = hex::decode(initial_value)
            .map_err(|e| PluginError::InputError(format!("Failed to decode initial value: {}", e)))?;

        for log_value in log_values {
            let mut hasher = openssl::hash::Hasher::new(digest_alg)
                .map_err(|e| PluginError::InternalError(format!("Failed to create hasher: {}", e)))?;

            hasher.update(&current_value)
                .map_err(|e| PluginError::InternalError(format!("Failed to update hash with current value: {}", e)))?;

            let log_bytes = hex::decode(log_value)
                .map_err(|e| PluginError::InputError(format!("Failed to decode log value: {}", e)))?;

            hasher.update(&log_bytes)
                .map_err(|e| PluginError::InternalError(format!("Failed to update hash with log value: {}", e)))?;

            current_value = hasher.finish()
                .map_err(|e| PluginError::InternalError(format!("Failed to finalize hash: {}", e)))?
                .to_vec();
        }

        Ok(hex::encode(current_value))
    }

    /// Calculates the final PCR value by extending log entries according to TPM's PCR extension logic
    pub fn replay_with_target(
        algorithm: &str,
        initial_value: &str,
        target_value: &str,
        log_values: &Vec<String>
    ) -> Result<String, PluginError> {
        let digest_alg = CryptoVerifier::hash_str_to_message_digest(algorithm)?;

        let target_value = hex::decode(target_value)
            .map_err(|e| PluginError::InputError(format!("Failed to decode target value: {}", e)))?;

        let mut current_value = hex::decode(initial_value)
            .map_err(|e| PluginError::InputError(format!("Failed to decode initial value: {}", e)))?;
        
        for log_value in log_values {
            let log_bytes = hex::decode(log_value)
                .map_err(|e| PluginError::InputError(format!("Failed to decode log value: {}", e)))?;

            let log_bytes = if log_bytes.iter().all(|b| *b == 0) {
                // Create a new vector filled with 0xff instead of trying to modify the existing one
                vec![0xff; log_bytes.len()]
            } else {
                log_bytes
            };
            
            let mut hasher = openssl::hash::Hasher::new(digest_alg)
                .map_err(|e| PluginError::InternalError(format!("Failed to create hasher: {}", e)))?;

            hasher.update(&current_value)
                .map_err(|e| PluginError::InternalError(format!("Failed to update hash with current value: {}", e)))?;

            hasher.update(&log_bytes)
                .map_err(|e| PluginError::InternalError(format!("Failed to update hash with log value: {}", e)))?;

            current_value = hasher.finish()
                .map_err(|e| PluginError::InternalError(format!("Failed to finalize hash: {}", e)))?
                .to_vec();
            
            if current_value == target_value {
                break;
            }
        }

        Ok(hex::encode(current_value))
    }

    /// Create initial PCR value based on PCR index according to TPM 2.0 specification:
    /// PCR 0-15: initialize with all zeros (platform firmware and configuration)
    /// PCR 16: initialize with all zeros (debug)
    /// PCR 17-22: initialize with all ones (platform specific)
    /// PCR 23: initialize with all zeros (application support)
    /// PCR 0: locality information is included in the last byte if provided
    ///
    /// # Arguments
    /// * `hash_alg` - The hash algorithm name
    /// * `pcr_index` - The PCR index (0-23)
    /// * `locality` - The locality value (only used for PCR 0)
    ///
    /// # Returns
    /// * `Result<String, PluginError>` - The initial PCR value or an error
    pub fn create_initial_pcr_value(hash_alg: &str, pcr_index: u32, locality: Option<u8>) -> Result<String, PluginError> {
        let digest_size = match hash_alg {
            "sha1" => 20,
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            "sm3" => 32,
            _ => return Err(PluginError::InputError(format!("Unsupported hash algorithm: {}", hash_alg))),
        };

        let mut initial_value = if pcr_index <= 15 || pcr_index == 16 || pcr_index == 23 {
            // PCR 0-15, 16, and 23: initialize with all zeros
            vec![0u8; digest_size]
        } else if pcr_index >= 17 && pcr_index <= 22 {
            // PCR 17-22: initialize with all ones
            vec![0xffu8; digest_size]
        } else {
            return Err(PluginError::InputError(format!("Invalid PCR index: {}", pcr_index)));
        };

        // For PCR 0, include locality information in the last byte if provided
        if pcr_index == 0 {
            if let Some(loc) = locality {
                initial_value[digest_size - 1] = loc;
            }
        }
        
        Ok(initial_value
            .into_iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>())
    }

    /// Set the PCR value for a given index. If the entry exists, update it; otherwise, insert a new entry.
    pub fn set_pcr_value(&mut self, index: u32, value: String) {
        if let Some(entry) = self.pcr_values.iter_mut().find(|e| e.pcr_index == index) {
            entry.pcr_value = value;
        } else {
            self.pcr_values.push(PcrValueEntry {
                pcr_index: index,
                pcr_value: value,
                replay_value: None,
                is_matched: None,
            });
        }
    }
}
