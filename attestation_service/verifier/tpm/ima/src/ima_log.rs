use serde_json::Value;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tpm_common_verifier::PcrValues;
use plugin_manager::{PluginError, ServiceHostFunctions};
use std::str::{self, FromStr};
use std::fs::File;
use std::io::{Write, Read};

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
    pub fn new(log_data: &str) -> Result<Self, PluginError> {
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
                Ok(10) => 10, // We only support PCR 10 for IMA
                Ok(_) => return Err(PluginError::InputError("Unsupported PCR index, only PCR 10 is supported for IMA".to_string())),
                Err(_) => return Err(PluginError::InputError("Invalid PCR index".to_string())),
            };
            
            let template_hash = parts[1].to_string();
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

    pub async fn verify(&mut self, pcr_values: &mut PcrValues, service_host_functions: &ServiceHostFunctions, user_id: &str) -> Result<bool, PluginError> {
        // First, replay using template_hash values to update PCR replay values
        self.replay_pcr_values(pcr_values)?;
        
        // Check if PCR values match replay values and update is_matched fields
        let pcr_match_result = pcr_values.check_is_matched()?;
        
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
        
        Ok(pcr_match_result)
    }

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
    pub fn replay_pcr_values(&self, pcr_values: &mut PcrValues) -> Result<(), PluginError> {
        // First, check if there are any logs to process
        if self.logs.is_empty() {
            return Ok(());
        }
        // Get the PCR index from the first log (all logs should have the same PCR index for IMA)
        let pcr_index = self.logs[0].pcr_index;

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
        
        // Collect all template hashes from the logs
        let template_hashes: Vec<String> = self.logs.iter()
            .map(|log| log.template_hash.clone())
            .collect();
        
        // Calculate the replay value by extending with all template hashes at once
        let replay_value = PcrValues::replay_with_target(
            &pcr_values.hash_alg,
            &initial_value,
            &pcr_values.get_pcr_value(pcr_index).unwrap(),
            &template_hashes,
        )?;
        
        // Update the replay value in the PCR values
        pcr_values.update_replay_value(pcr_index, replay_value);
        
        Ok(())
    }
}