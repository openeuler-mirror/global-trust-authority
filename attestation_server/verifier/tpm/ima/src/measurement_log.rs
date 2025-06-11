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

use serde_json::Value;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tpm_common_verifier::PcrValues;
use tpm_common_verifier::CryptoVerifier;
use plugin_manager::{PluginError, ServiceHostFunctions};
use std::str::{self, FromStr};
use openssl::hash::Hasher;
use hex;

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

            let template_hash = Self::calculate_template_hash(&file_hash, &file_hash_alg, &file_path, template_hash_alg)?;
            
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
        .map_err(|e| PluginError::InputError(
            format!("Unsupported hash algorithm: {}, error: {}", hash_alg, e)
        ))?;
        let mut hasher = Hasher::new(digest_alg)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to create hasher: {}", e)
            ))?;
        hasher.update(&(hash_bytes.len() as u32).to_le_bytes()).expect("update hash_bytes failed!");
        hasher.update(hash_bytes).expect("update hash_bytes failed!");
        hasher.update(&(name_bytes.len() as u32).to_le_bytes()).expect("update name_bytes failed!");
        hasher.update(name_bytes).expect("update name_bytes failed!");
        match hasher.finish() {
            Ok(digest) => Ok(hex::encode(digest)),
            Err(e) => Err(PluginError::InternalError(format!("Failed to finish hashing: {}", e)))
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
        result.push(0);  // Extra null byte (bug in Java code)
        result.extend_from_slice(&hash_bytes);
        
        Ok(result)
    }
    
    fn get_name_bytes(file_name: &str) -> Vec<u8> {
        let mut bytes = file_name.as_bytes().to_vec();
        bytes.push(0);  // Null terminator
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
    /// * `Result<bool, PluginError>` - Success or error
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InternalError` - Failed to get unmatched measurements
    pub async fn verify(&mut self, pcr_values: &mut PcrValues, service_host_functions: &ServiceHostFunctions, user_id: &str) -> Result<bool, PluginError> {
        // First, replay using template_hash values to update PCR replay values
        self.replay_pcr_values(pcr_values)?;
        
        // Check if PCR values match replay values and update is_matched fields
        let mut pcr_match_result = pcr_values.check_is_matched()?;
        
        // Extract file hashes from logs, skipping 'boot_aggregate' entries
        let file_hashes: Vec<String> = self.logs.iter()
            .filter(|log| log.file_path != "boot_aggregate" && !log.template_hash.chars().all(|c| c == '0'))
            .map(|log| log.file_hash.clone())
            .collect();
        
        // Call the get_unmatched_measurements function pointer to check reference values
        let unmatched_hashes: std::collections::HashSet<String> = match (service_host_functions
            .get_unmatched_measurements)(&file_hashes, "tpm_ima", user_id).await {
                Ok(values) => values.into_iter().collect(),
                Err(err) => return Err(PluginError::InternalError(format!("Failed to get unmatched measurements: {}", err))),
            };
            
        // Update ref_value_matched in logs based on unmatched hashes
        for log in &mut self.logs {
            log.ref_value_matched = Some(!unmatched_hashes.contains(&log.file_hash));
        }

        // If there are any unmatched hashes, set pcr_match_result to false
        if !unmatched_hashes.is_empty() {
            pcr_match_result = false;
        }
        
        Ok(pcr_match_result)
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

    /// Replay PCR values using template_hash values from IMA logs
    ///
    /// This function replays the PCR values by extending them with template_hash values
    /// from the IMA logs, updating the replay_value field in each PCR entry.
    ///
    /// # Parameters
    /// * `pcr_values` - PCR values to update
    ///
    /// # Returns
    /// * `Result<(), PluginError>` - Success or error
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the hash algorithm is not supported
    pub fn replay_pcr_values(&self, pcr_values: &mut PcrValues) -> Result<(), PluginError> {
        // First, check if there are any logs to process
        if self.logs.is_empty() {
            return Ok(());
        }

        // Get the digest size based on the hash algorithm
        let digest_size = match pcr_values.hash_alg.as_str() {
            "sha1" => 20,
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            _ => return Err(PluginError::InputError("Unsupported hash algorithm".to_string())),
        };
        
        // Create the initial PCR value (all zeros)
        let initial_value = vec![0u8; digest_size].into_iter().map(|b| format!("{:02x}", b)).collect::<String>();
        
        // Group template hashes by PCR index
        let mut pcr_template_hashes: std::collections::HashMap<u32, Vec<String>> = std::collections::HashMap::new();
        
        // Collect template hashes for each PCR index
        for log in &self.logs {
            pcr_template_hashes
                .entry(log.pcr_index)
                .or_insert_with(Vec::new)
                .push(log.template_hash.clone());
        }
        
        // Calculate replay value for each PCR index
        for (pcr_index, template_hashes) in pcr_template_hashes {
            // Skip if PCR value doesn't exist in pcr_values
            let pcr_value = match pcr_values.get_pcr_value(pcr_index) {
                Some(value) => value,
                None => continue,
            };
            
            // Calculate the replay value by extending with all template hashes for this PCR index
            let replay_value = PcrValues::replay_with_target(
                &pcr_values.hash_alg,
                &initial_value,
                pcr_value,
                &template_hashes,
            )?;
            
            // Update the replay value in the PCR values
            pcr_values.update_replay_value(pcr_index, replay_value);
        }
        
        Ok(())
    }
}