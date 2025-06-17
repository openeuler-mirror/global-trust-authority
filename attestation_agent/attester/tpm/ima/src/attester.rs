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

// TPM IMA plugin implementation
use tpm_common_attester::{TpmPluginBase, TpmPluginConfig, Log};
use plugin_manager::{AgentPlugin, PluginError, PluginBase, QueryConfigurationFn, AgentHostFunctions};
use std::fs::File;
use std::io::{BufRead, BufReader};
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Maximum number of lines allowed in an IMA log file
const MAX_IMA_LOG_LINES: usize = 20000;

#[derive(Debug)]
pub struct TpmImaPlugin {
    config: TpmPluginConfig,
}

impl TpmImaPlugin {
    /// Creates a new instance of the attester.
    ///
    /// # Parameters
    ///
    /// * `plugin_type` - The type of the plugin.
    /// * `query_configuration` - A function to query the configuration.
    ///
    /// # Returns
    ///
    /// * `Result<Self, PluginError>` - Success returns a new instance of the attester,
    ///   failure returns an appropriate error.
    ///
    /// # Errors
    ///
    /// Returns an error if the attester cannot be created.
    pub fn new(plugin_type: String, query_configuration: QueryConfigurationFn) -> Result<Self, PluginError> {
        if plugin_type != "tpm_ima" {
            return Err(PluginError::InputError("Invalid plugin type".to_string()));
        }
        // Get plugin config by plugin type
        let plugin_config = (query_configuration)(plugin_type.clone())
            .ok_or_else(|| PluginError::InternalError("Plugin configuration not found".to_string()))?;
        
        // Parse the configuration using the common config structure
        let config = TpmPluginConfig::from_json(plugin_type, &plugin_config)?;
        Ok(Self { config })
    }
}

impl PluginBase for TpmImaPlugin {
    fn plugin_type(&self) -> &str {
        self.config.plugin_type.as_str()
    }
}

impl AgentPlugin for TpmImaPlugin {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<serde_json::Value, PluginError> {
        // Use the common implementation from the trait
        self.collect_evidence_impl(node_id, nonce)
    }
}

impl TpmPluginBase for TpmImaPlugin {
    fn config(&self) -> &TpmPluginConfig {
        &self.config
    }
    
    // Implement the collect_log method for IMA plugin
    fn collect_log(&self) -> Result<Vec<Log>, PluginError> {
        // Open the IMA log file
        let file = File::open(&self.config.log_file_path).map_err(|e| {
            PluginError::InternalError(format!("Failed to open IMA log file: {}", e))
        })?;
        
        let mut reader = BufReader::new(file);
        let mut line_count = 0;
        let mut buffer = Vec::new();

        // Read the file line by line to count lines and collect content
        let mut line = String::new();
        while reader.read_line(&mut line).map_err(|e| {
            PluginError::InternalError(format!("Failed to read IMA log file: {}", e))
        })? > 0 {
            line_count += 1;

            // Check line count after reading
            if line_count > MAX_IMA_LOG_LINES {
                return Err(PluginError::InternalError(
                    format!("IMA log file exceeds maximum allowed lines: {} > {}", line_count, MAX_IMA_LOG_LINES)
                ));
            }
            buffer.extend_from_slice(line.as_bytes());
            line.clear(); // Clear the buffer for the next line
        }

        // Encode the binary data as base64 string
        let log_data = STANDARD.encode(&buffer);
        
        Ok(vec![Log {
            log_type: String::from("ImaLog"),
            log_data,
        }])
    }
}

// Each plugin has its own create_plugin function
#[no_mangle]
pub fn create_plugin(host_functions: &AgentHostFunctions, plugin_type: &str) -> Option<Box<dyn AgentPlugin>> {
    // Extract the functions from the host functions struct
    let query_configuration = host_functions.query_configuration;
    
    // Create a new instance with the host functions
    match TpmImaPlugin::new(String::from(plugin_type), query_configuration) {
        Ok(plugin) => Some(Box::new(plugin)),
        Err(e) => {
            log::error!("Failed to create plugin: {}", e);
            None
        }
    }
}