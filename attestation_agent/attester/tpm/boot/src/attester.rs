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

// TPM Boot plugin implementation
use tpm_common_attester::{TpmPluginBase, TpmPluginConfig, Log};
use plugin_manager::{AgentPlugin, PluginError, PluginBase, QueryConfigurationFn, AgentHostFunctions};
use std::fs::File;
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Debug)]
pub struct TpmBootPlugin {
    config: TpmPluginConfig,
}

impl TpmBootPlugin {
    pub fn new(plugin_type: String, query_configuration: QueryConfigurationFn) -> Result<Self, PluginError> {
        if plugin_type != "tpm_boot" {
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

impl PluginBase for TpmBootPlugin {
    fn plugin_type(&self) -> &str {
        self.config.plugin_type.as_str()
    }
}

impl AgentPlugin for TpmBootPlugin {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<serde_json::Value, PluginError> {
        // Use the common implementation from the trait
        self.collect_evidence_impl(node_id, nonce)
    }
}

impl TpmPluginBase for TpmBootPlugin {
    fn config(&self) -> &TpmPluginConfig {
        &self.config
    }
    
    // Implement the collect_log method for boot plugin
    fn collect_log(&self) -> Result<Vec<Log>, PluginError> {
        // Open the boot log file
        let file = File::open(&self.config.log_file_path).map_err(|e| {
            PluginError::InternalError(format!("Failed to open boot log file: {}", e))
        })?;

        // Check file size before reading
        let metadata = file.metadata().map_err(|e| {
            PluginError::InternalError(format!("Failed to get file metadata: {}", e))
        })?;
        
        // 5MiB = 5 * 1024 * 1024 bytes
        const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;
        
        if metadata.len() > MAX_FILE_SIZE {
            return Err(PluginError::InternalError(
                format!("Boot log file size ({} bytes) exceeds maximum allowed size (5 MiB)",
                    metadata.len())
            ));
        }

        // Read file contents into a buffer
        let buffer = std::fs::read(&self.config.log_file_path).map_err(|e| {
            PluginError::InternalError(format!("Failed to read boot log file: {}", e))
        })?;
        
        // Encode the binary data as base64 string using the new API
        let log_data = STANDARD.encode(&buffer);
        
        Ok(vec![Log {
            log_type: String::from("TcgEventLog"),
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
    match TpmBootPlugin::new(String::from(plugin_type), query_configuration) {
        Ok(plugin) => Some(Box::new(plugin)),
        Err(e) => {
            log::error!("Failed to create plugin: {}", e);
            None
        }
    }
}