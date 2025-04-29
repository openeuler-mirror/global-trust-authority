use serde_json::Value;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tpm_common_verifier::PcrValues;
use plugin_manager::{PluginError, ServiceHostFunctions};
use std::str::{self, FromStr};

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
        for log in &mut self.logs {
            // Find the PCR value with the matching index
            let pcr_index = log.pcr_index;
            let pcr_value = pcr_values.pcr_values.iter()
                .find(|pcr| pcr.pcr_index == pcr_index)
                .ok_or_else(|| PluginError::InputError(format!("PCR index {} not found in PCR values", pcr_index)))?;
            
            // Create a vector with a single file hash for the replay function
            let file_hashes = vec![log.file_hash.clone()];
            
            let replay_value = PcrValues::replay(
                &pcr_values.hash_alg,
                &pcr_value.pcr_value,
                &file_hashes,
            )?;
            log.ref_value_matched = Some(pcr_value.pcr_value == replay_value);
        }
        
        // Extract file hashes from logs
        let file_hashes: Vec<String> = self.logs.iter().map(|log| log.file_hash.clone()).collect();
        
        // Call the get_unmatched_measurements function pointer
        let unmatched_hashes: std::collections::HashSet<String> = (service_host_functions
            .get_unmatched_measurements)(&file_hashes, "tpm_ima", user_id).await
            .into_iter()
            .collect();
            
        for log in &mut self.logs {
            log.ref_value_matched = Some(!unmatched_hashes.contains(&log.file_hash));
        }
        Ok(true)
    }

    pub fn to_json_value(&self) -> Result<Value, PluginError> {
        serde_json::to_value(self).map_err(|e| PluginError::InternalError(e.to_string()))
    }
}