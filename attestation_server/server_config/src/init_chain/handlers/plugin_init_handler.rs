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

use std::{future::Future, pin::Pin};

use common_log::info;
use std::collections::HashMap;
use std::sync::OnceLock;

use config_manager::types::context::CONFIG;
use endorserment::services::cert_service::CertService;
use common_log::error;
use plugin_manager::PluginManager;
use plugin_manager::PluginManagerInstance;
use plugin_manager::ServiceHostFunctions;
use plugin_manager::ServicePlugin;
use rv::services::rv_trait::RefValueTrait;
use rv::services::rv_factory::RvFactory;

use crate::init_chain::traits::{InitContext, InitHandler};


// Global plugin configuration storage
static LAZY_PLUGIN_CONFIG: OnceLock<HashMap<String, String>> = OnceLock::new();

#[derive(Debug)]
pub struct PluginInitHandler {
    next: Option<Box<dyn InitHandler>>,
}

impl PluginInitHandler {
    pub fn new() -> PluginInitHandler {
        PluginInitHandler { next: None }
    }

    pub fn init_plugin(&self) -> Result<(), Box<dyn std::error::Error>> {
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
            get_unmatched_measurements: Box::new(|measured_values, attester_type, user_id| {
                Box::pin(async move {
                    // The verify method now returns a Result<Vec<String>, String>
                    let unmatch = RvFactory::create_ref_value().verify(measured_values, user_id, attester_type).await?;
                    info!("Unmatched measurements length: {:?}", unmatch.len());
                    Ok(unmatch)
                })
            }),
            query_configuration: |plugin_name| {LAZY_PLUGIN_CONFIG.get().and_then(|config| config.get(&plugin_name)).cloned()},
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
}

impl InitHandler for PluginInitHandler {
    fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
        Box::pin(async move {
            let _ = self.init_plugin();
            if let Some(next) = &self.next {
                next.handle(context).await
            } else {
                Ok(())
            }
        })
    }

    fn set_next(&mut self, next: Box<dyn InitHandler>) {
        self.next = Some(next);
    }
}
