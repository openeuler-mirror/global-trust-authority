use std::collections::HashMap;
use log::{error, info};
use plugin_manager::{
    PluginManager,
    AgentPlugin,
    PluginManagerInstance,
    AgentHostFunctions
};
use config::{
    Config,
    ConfigManager,
    AGENT_CONFIG
};
use agent_utils::AgentError;

/// Configuration query function for plugin manager
/// This function will be dynamically called by the plugin manager
/// Returns the serialized params for a given plugin name if found
pub fn query_configuration(plugin_name: String) -> Option<String> {
    // Get the global agent configuration instance
    let config = match AGENT_CONFIG.get_instance() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to get config: {}", e);
            return None;
        }
    };

    // Find the plugin config matching the given plugin name
    let plugin = config.plugins.iter().find(|p| p.name == plugin_name)?;

    // Get and serialize the plugin parameters to JSON string
    let params = match &plugin.params {
        Some(params) => match ConfigManager::to_json(params) {
            Ok(json) => Some(json),
            Err(e) => {
                error!("Failed to serialize plugin params: {}", e);
                None
            }
        },
        None => Some("null".to_string()) // If no params, return JSON null
    };

    params
}

/// Load and initialize plugins based on configuration
/// Iterates all plugins in config and loads them into the plugin manager
pub(crate) fn load_plugins(config: &Config) -> Result<(), AgentError> {
    // Get AgentPlugin manager instance
    let plugin_manager = PluginManager::<dyn AgentPlugin, AgentHostFunctions>::get_instance();

    let mut plugin_paths = HashMap::new();
    for plugin_config in &config.plugins {
        if !plugin_config.enabled {
            info!("Plugin {} is disabled, skipping", plugin_config.name);
            continue;
        }
        // Validate that the plugin file exists
        if !std::path::Path::new(&plugin_config.path).exists() {
            error!("Plugin file not found: {}", plugin_config.path);
            return Err(AgentError::PluginLoadError(format!("Plugin file not found: {}", plugin_config.path)));
        }

        plugin_paths.insert(plugin_config.name.clone(), plugin_config.path.clone());
    }

    if plugin_paths.is_empty() {
        error!("No enabled plugins found");
        return Err(AgentError::PluginLoadError("No enabled plugins found".to_string()));
    }

    // Create an instance of host functions for plugin initialization
    let host_functions = AgentHostFunctions::new(query_configuration);

    // Initialize the plugin manager with the discovered plugins and host functions
    if plugin_manager.initialize(&plugin_paths, &host_functions) {
        info!("Successfully loaded all plugins");
        Ok(())
    } else {
        Err(AgentError::PluginLoadError("Failed to initialize plugins".to_string()))
    }
}
