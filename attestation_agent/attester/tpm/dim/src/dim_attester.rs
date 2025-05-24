// TPM DIM plugin implementation
use tpm_common_attester::{TpmPluginBase, TpmPluginConfig, Log};
use plugin_manager::{AgentPlugin, PluginError, PluginBase, QueryConfigurationFn, AgentHostFunctions};
use serde_json;
use std::fs::File;
use std::io::Read;
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Debug)]
pub struct TpmDimPlugin {
    config: TpmPluginConfig,
}

impl TpmDimPlugin {
    pub fn new(plugin_type: String, query_configuration: QueryConfigurationFn) -> Result<Self, PluginError> {
        if plugin_type != "tpm_dim" {
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

impl PluginBase for TpmDimPlugin {
    fn plugin_type(&self) -> &str {
        self.config.plugin_type.as_str()
    }
}

impl AgentPlugin for TpmDimPlugin {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<serde_json::Value, PluginError> {
        // Use the common implementation from the trait
        self.collect_evidence_impl(node_id, nonce)
    }
}

impl TpmPluginBase for TpmDimPlugin {
    fn config(&self) -> &TpmPluginConfig {
        &self.config
    }
    
    // Implement the collect_log method for DIM plugin
    fn collect_log(&self) -> Result<Vec<Log>, PluginError> {
        // Open the DIM log file
        let mut file = File::open(&self.config.log_file_path).map_err(|e| {
            PluginError::InternalError(format!("Failed to open DIM log file: {}", e))
        })?;
        
        // Read file contents into a buffer
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).map_err(|e| {
            PluginError::InternalError(format!("Failed to read DIM log file: {}", e))
        })?;
        
        // Encode the binary data as base64 string using the new API
        let log_data = STANDARD.encode(&buffer);
        
        Ok(vec![Log {
            log_type: String::from("DimLog"),
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
    match TpmDimPlugin::new(String::from(plugin_type), query_configuration) {
        Ok(plugin) => Some(Box::new(plugin)),
        Err(e) => {
            log::error!("Failed to create plugin: {}", e);
            None
        }
    }
}