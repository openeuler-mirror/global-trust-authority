use std::collections::HashMap;
use std::sync::OnceLock;

use endorserment::services::cert_service::CertService;
use log::{error, info};
use std::pin::Pin;
use std::future::Future;
use crate::PluginManager;
use crate::PluginManagerInstance;
use crate::ServiceHostFunctions;
use crate::ServicePlugin;
use config_manager::types::context::CONFIG;

// Global plugin configuration storage
static LAZY_PLUGIN_CONFIG: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Initialize a plugin with configuration from yaml file
pub fn init_plugin() -> Result<(), Box<dyn std::error::Error>> {
    // Get config from CONFIG singleton
    let config = CONFIG.get_instance().map_err(|e| {
        error!("Failed to get config instance: {}", e);
        e
    })?;

    let mut plugin_paths = HashMap::new();
    for plugin in &config.attestation_service.plugins {
        plugin_paths.insert(plugin.name.clone(), plugin.path.clone());
        info!("Loaded verifier plugin: {} at path: {}", plugin.name, plugin.path);
    }
    if plugin_paths.is_empty() {
        let err = "No valid plugin configurations found in config";
        error!("{}", err);
        return Err(err.into());
    }

    // Runtime plugin configuration processing
    let plugin_config: HashMap<String, String> = config
        .attestation_service
        .plugins
        .iter()
        .map(|p| {
            let json_str = serde_json::to_string(&serde_json::json!({
                "name": p.name.clone(),
                "path": p.path.clone()
            }))
            .unwrap();
            (p.name.clone(), json_str)
        })
        .collect();
    LAZY_PLUGIN_CONFIG.set(plugin_config).map_err(|_| "Failed to set plugin config")?;

    // Create host functions
    let host_functions = ServiceHostFunctions {
        validate_cert_chain: Box::new(|cert_type, user_id, cert_data| {
            Box::pin(async move {
                CertService::verify_cert_chain(cert_type, user_id, cert_data).await.unwrap_or_else(|_| false)
            })
        }),
        get_unmatched_measurements: Box::new(
            |measured_values: &Vec<String>, _attester_type: &str, _user_id: &str| -> Pin<Box<dyn Future<Output = Vec<String>> + Send>> {
                let cloned = measured_values.clone();
                Box::pin(async move { cloned })
            }
        ),
        query_configuration: query_plugin_configuration,
    };

    // Get the plugin manager instance
    let manager = PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance();

    // Initialize the plugin manager
    let init_result: bool = manager.initialize(&plugin_paths, &host_functions);
    if !init_result {
        let err = "Failed to initialize plugin manager";
        error!("{}", err);
        return Err(err.into());
    }

    Ok(())
}

/// Function for querying plugin configuration
fn query_plugin_configuration(plugin_name: String) -> Option<String> {
    LAZY_PLUGIN_CONFIG.get().and_then(|config| config.get(&plugin_name)).cloned()
}

/// Check if the plugin manager is initialized
pub fn check_plugin_initialized() -> bool {
    let manager = PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance();
    manager.is_initialized()
}
