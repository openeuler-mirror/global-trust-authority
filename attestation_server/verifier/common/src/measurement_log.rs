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

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use openssl::hash::Hasher;
use plugin_manager::{PluginError, ServiceHostFunctions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::str::{self, FromStr};
use tpm_common_verifier::CryptoVerifier;
use tpm_common_verifier::PcrValueEntry;
use tpm_common_verifier::PcrValues;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaLogEntry {
    pub pcr_index: u32,
    pub template_hash: String,
    pub template_name: String,
    pub file_hash_alg: String,
    pub file_hash: String,
    pub file_path: String,
    pub ref_value_matched: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaLog {
    pub logs: Vec<ImaLogEntry>,
}

impl ImaLog {
    /// Create ImaLog from base64 encoded ima log data
    ///
    /// # Arguments
    ///
    /// * `log_data` - Base64 encoded ima log data
    /// * template_hash_alg - Hash algorithm for template hash calculation
    ///
    /// # Returns
    ///
    /// * `Result<ImaLog, PluginError>` - ImaLog on success, error on failure
    ///
    /// # Errors
    ///
    /// * `PluginError::InputError` - If the log data is not valid
    pub fn new(log_data: &str, template_hash_alg: &str) -> Result<Self, PluginError> {
        let log_data = match BASE64.decode(log_data) {
            Ok(data) => data,
            Err(_) => return Err(PluginError::InputError("Failed to decode base64 log data".to_string())),
        };

        // Convert bytes to string
        let log_str = match str::from_utf8(&log_data) {
            Ok(s) => s,
            Err(_) => return Err(PluginError::InputError("Failed to convert log data to string".to_string())),
        };

        // Parse each line of the log
        let mut logs = Vec::new();
        for line in log_str.lines() {
            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Parse line format: "pcr_index template_hash template_name file_hash_alg:file_hash file_path"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                return Err(PluginError::InputError("Invalid log format".to_string()));
            }

            // Parse PCR index
            let pcr_index = match u32::from_str(parts[0]) {
                Ok(value) => value,
                Err(_) => return Err(PluginError::InputError("Invalid PCR index".to_string())),
            };

            let template_name = parts[2].to_string();

            // Parse file hash which is in format "alg:hash"
            let hash_parts: Vec<&str> = parts[3].split(':').collect();
            if hash_parts.len() != 2 {
                return Err(PluginError::InputError("Invalid hash format".to_string()));
            }

            let file_hash_alg = hash_parts[0].to_string();
            let file_hash = hash_parts[1].to_string();

            // Combine remaining parts as file path
            let file_path = parts[4].to_string();

            let logged_template_hash = parts[1].to_string();
            let template_hash = match logged_template_hash.chars().all(|c| c == '0') {
                false => Self::calculate_template_hash(&file_hash, &file_hash_alg, &file_path, template_hash_alg)?,
                true => {
                    let digest_size = CryptoVerifier::hash_str_to_digest_size(&template_hash_alg)
                        .map_err(|e| PluginError::InputError(format!("Failed to get digest size: {}", e)))?;
                    "0".repeat(digest_size * 2)
                },
            };

            logs.push(ImaLogEntry {
                pcr_index,
                template_hash,
                template_name,
                file_hash_alg,
                file_hash,
                file_path,
                ref_value_matched: None,
            });
        }
        Ok(Self { logs })
    }

    fn calculate_template_hash(
        file_hash: &str,
        file_hash_alg: &str,
        file_name: &str,
        template_hash_alg: &str,
    ) -> Result<String, PluginError> {
        // 1. Get hash bytes with algorithm prefix
        let hash_bytes = Self::get_hash_bytes(file_hash, file_hash_alg)?;

        // 2. Get filename bytes with null terminator
        let name_bytes = Self::get_name_bytes(file_name);

        // 3. Calculate hash with the specified algorithm
        Self::calculate_hash(template_hash_alg, &hash_bytes, &name_bytes)
    }

    fn calculate_hash(hash_alg: &str, hash_bytes: &[u8], name_bytes: &[u8]) -> Result<String, PluginError> {
        let digest_alg = CryptoVerifier::hash_str_to_message_digest(hash_alg)
            .map_err(|e| PluginError::InputError(format!("Unsupported hash algorithm: {}, error: {}", hash_alg, e)))?;
        let mut hasher = Hasher::new(digest_alg)
            .map_err(|e| PluginError::InternalError(format!("Failed to create hasher: {}", e)))?;
        hasher.update(&(hash_bytes.len() as u32).to_le_bytes()).expect("update hash_bytes failed!");
        hasher.update(hash_bytes).expect("update hash_bytes failed!");
        hasher.update(&(name_bytes.len() as u32).to_le_bytes()).expect("update name_bytes failed!");
        hasher.update(name_bytes).expect("update name_bytes failed!");
        match hasher.finish() {
            Ok(digest) => Ok(hex::encode(digest)),
            Err(e) => Err(PluginError::InternalError(format!("Failed to finish hashing: {}", e))),
        }
    }

    fn get_hash_bytes(file_hash: &str, file_hash_alg: &str) -> Result<Vec<u8>, PluginError> {
        let alg_prefix = format!("{}:", file_hash_alg.to_lowercase());
        let hash_bytes = match hex::decode(file_hash.trim()) {
            Ok(value) => value,
            Err(err) => return Err(PluginError::InternalError(format!("Hex decoding file hash failed: {}", err))),
        };

        let mut result = Vec::with_capacity(alg_prefix.len() + 1 + hash_bytes.len());
        result.extend_from_slice(alg_prefix.as_bytes());
        result.push(0); // Extra null byte (bug in Java code)
        result.extend_from_slice(&hash_bytes);

        Ok(result)
    }

    fn get_name_bytes(file_name: &str) -> Vec<u8> {
        let mut bytes = file_name.as_bytes().to_vec();
        bytes.push(0); // Null terminator
        bytes
    }

    /// Verify the IMA log against PCR values and reference values
    ///
    /// # Arguments
    ///
    /// * `pcr_values` - PCR values to verify against
    /// * `service_host_functions` - Service host functions
    /// * `user_id` - User ID
    ///
    /// # Returns
    ///
    /// * `Result<(bool, bool), PluginError>` - (PCR replay result, Reference value match result)
    ///
    /// # Errors
    ///
    /// * `PluginError::InternalError` - Failed to get unmatched measurements
    pub async fn verify(
        &mut self,
        pcr_values: &mut PcrValues,
        service_host_functions: &ServiceHostFunctions,
        user_id: &str,
    ) -> Result<(bool, bool), PluginError> {
        // First, replay using template_hash values to update PCR replay values
        self.replay_pcr_values(pcr_values)?;

        // Check if PCR values match replay values and update is_matched fields
        let replay_result = pcr_values.check_is_matched()?;

        let ref_value_result = self.check_reference_values(service_host_functions, user_id, "tpm_ima").await?;

        Ok((replay_result, ref_value_result))
    }

    /// Convert ImaLog to JSON Value
    ///
    /// # Returns
    ///
    /// * `Result<Value, PluginError>` - JSON Value on success, error on failure
    ///
    /// # Errors
    ///
    /// * `PluginError::InternalError` - Failed to convert to JSON Value
    pub fn to_json_value(&self) -> Result<Value, PluginError> {
        serde_json::to_value(self).map_err(|e| PluginError::InternalError(e.to_string()))
    }

    fn calculate_replay_values_map(&self, pcr_values_input: &PcrValues) -> Result<HashMap<u32, String>, PluginError> {
        if self.logs.is_empty() {
            return Ok(HashMap::new());
        }

        let digest_size = match pcr_values_input.hash_alg.as_str() {
            "sha1" => 20,
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            _ => return Err(PluginError::InputError("Unsupported hash algorithm".to_string())),
        };

        let initial_value = vec![0u8; digest_size].into_iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let mut pcr_template_hashes: HashMap<u32, Vec<String>> = HashMap::new();

        for log in &self.logs {
            let processed_hash = if log.template_hash.chars().all(|c| c == '0') {
                "f".repeat(log.template_hash.len())
            } else {
                log.template_hash.clone()
            };

            pcr_template_hashes.entry(log.pcr_index).or_insert_with(Vec::new).push(processed_hash);
        }

        let mut replay_value_map = HashMap::new();
        for (pcr_index, template_hashes) in pcr_template_hashes {
            let pcr_value = match pcr_values_input.get_pcr_value(pcr_index) {
                Some(value) => value,
                None => continue,
            };

            let replay_value =
                PcrValues::replay_with_target(&pcr_values_input.hash_alg, &initial_value, pcr_value, &template_hashes)?;

            replay_value_map.insert(pcr_index, replay_value);
        }
        Ok(replay_value_map)
    }

    /// Replays PCR values based on the measurement log.
    ///
    /// This function calculates the replay values for each PCR index present in the measurement log
    /// and updates the provided `PcrValues` structure with these new replay values.
    ///
    /// # Arguments
    ///
    /// * `pcr_values` - A mutable reference to a `PcrValues` struct that will be updated
    ///                  with the calculated replay values.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the PCR values are successfully replayed.
    /// * `Err(PluginError)` - If an error occurs during the replay process, such as an unsupported
    ///                         hash algorithm or an issue with PCR value calculation.
    pub fn replay_pcr_values(&self, pcr_values: &mut PcrValues) -> Result<(), PluginError> {
        let replay_map = self.calculate_replay_values_map(pcr_values)?;
        for (pcr_index, replay_value) in replay_map {
            pcr_values.update_replay_value(pcr_index, replay_value);
        }
        Ok(())
    }

    /// Calculates and returns a map of PCR indices to their replayed values.
    ///
    /// This function takes a vector of PCR value strings and a hash algorithm, constructs a
    /// temporary `PcrValues` object, and then calculates the replayed values for each PCR index
    /// based on the measurement log.
    ///
    /// # Arguments
    ///
    /// * `pcr_values` - A `Vec<String>` where each string represents a PCR value.
    /// * `hash_alg` - The hash algorithm used for PCR calculations (e.g., "sha256").
    ///
    /// # Returns
    ///
    /// * `Ok(HashMap<u32, String>)` - A hash map where keys are PCR indices (`u32`)
    ///                                 and values are their replayed hexadecimal string values.
    /// * `Err(PluginError)` - If an error occurs during the calculation, such as an unsupported
    ///                         hash algorithm or an issue with PCR value processing.
    pub fn get_replay_pcr_values(
        &self,
        pcr_values: Vec<String>,
        hash_alg: &str,
    ) -> Result<HashMap<u32, String>, PluginError> {
        let mut temp_pcr_entries = Vec::new();
        for (i, pcr_val_str) in pcr_values.into_iter().enumerate() {
            temp_pcr_entries.push(PcrValueEntry {
                pcr_index: i as u32 + 1u32,
                pcr_value: pcr_val_str,
                replay_value: None,
                is_matched: None,
            });
        }
        let temp_pcr_values = PcrValues { hash_alg: hash_alg.to_string(), pcr_values: temp_pcr_entries };
        self.calculate_replay_values_map(&temp_pcr_values)
    }

    /// Checks the measurement log entries against reference values provided by the service host functions.
    ///
    /// This function extracts file hashes from the logs (skipping 'boot_aggregate' entries),
    /// calls an external service to get unmatched measurements, and then updates the
    /// `ref_value_matched` field for each log entry based on whether its hash is found
    /// in the unmatched list. Finally, it returns a boolean indicating if all reference
    /// values are matched.
    ///
    /// # Arguments
    ///
    /// * `service_host_functions` - A reference to `ServiceHostFunctions` which provides
    ///                                 the `get_unmatched_measurements` function pointer.
    /// * `user_id` - A string slice representing the ID of the user for whom the measurements
    ///               are being checked.
    /// * `plugin_name` - A string slice indicating the name of the plugin (e.g., "tpm_ima", "virt_cca")
    ///                   to be used when calling `get_unmatched_measurements`.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If all relevant log entries have their file hashes matched against
    ///                the reference values (i.e., no unmatched hashes are found).
    /// * `Ok(false)` - If one or more relevant log entries have file hashes that do not match
    ///                 the reference values.
    /// * `Err(PluginError::InternalError)` - If there is a failure in calling the external
    ///                                         `get_unmatched_measurements` function or
    ///                                         processing its result.
    pub async fn check_reference_values(
        &mut self,
        service_host_functions: &ServiceHostFunctions,
        user_id: &str,
        plugin_name: &str,
    ) -> Result<bool, PluginError> {
        // Extract file hashes from logs, skipping 'boot_aggregate' entries
        let file_hashes: Vec<String> = self
            .logs
            .iter()
            .filter(|log| log.file_path != "boot_aggregate" && !log.template_hash.chars().all(|c| c == '0'))
            .map(|log| log.file_hash.clone())
            .collect();

        // Call the get_unmatched_measurements function pointer to check reference values
        let unmatched_hashes: std::collections::HashSet<String> =
            match (service_host_functions.get_unmatched_measurements)(&file_hashes, plugin_name, user_id).await {
                Ok(values) => values.into_iter().collect(),
                Err(err) => {
                    return Err(PluginError::InternalError(format!("Failed to get unmatched measurements: {}", err)))
                },
            };

        // Update ref_value_matched in logs based on unmatched hashes
        for log in &mut self.logs {
            log.ref_value_matched = Some(!unmatched_hashes.contains(&log.file_hash));
        }

        // If there are any unmatched hashes, set pcr_match_result to false
        let ref_value_result = if !unmatched_hashes.is_empty() { false } else { true };
        Ok(ref_value_result)
    }
}
