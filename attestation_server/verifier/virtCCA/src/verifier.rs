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

use std::error::Error;

use async_trait::async_trait;
use plugin_manager::{PluginBase, PluginError, ServiceHostFunctions, ServicePlugin};
use serde_json::Value;

use crate::evidence::VritCCAEvidence;

/// Represents the VirtCCA plugin for verification services.
pub struct VirtCCAPlugin {
    plugin_type: String,
    service_host_functions: ServiceHostFunctions,
}

impl VirtCCAPlugin {
    /// Creates a new instance of `VirtCCAPlugin`.
    ///
    /// # Parameters
    /// - `plugin_type`: The type of the plugin as a `String`.
    /// - `service_host_functions`: The host functions for the service.
    ///
    /// # Returns
    /// A new `VirtCCAPlugin` instance.
    pub fn new(
        plugin_type: String, 
        service_host_functions: ServiceHostFunctions,
    ) -> Self {
        Self {
            plugin_type,
            service_host_functions,
        }
    }

    /// Returns a reference to the service host functions.
    ///
    /// # Returns
    /// A reference to `ServiceHostFunctions`.
    pub fn get_host_functions(&self) -> &ServiceHostFunctions {
        &self.service_host_functions
    }

    /// Returns the plugin type as a string slice.
    ///
    /// # Returns
    /// A `&str` representing the plugin type.
    pub fn get_plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

impl PluginBase for VirtCCAPlugin {
    fn plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

#[async_trait]
impl ServicePlugin for VirtCCAPlugin {
    fn get_sample_output(&self) -> Value {
        serde_json::from_str(
            r#"{
                "evidence": {
                    "vcca_token": "test_token",
                    "dev_cert": "test_cert",
                    "logs": [
                        {
                            "log_type": "ImaLog",
                            "log_data": "test_log"
                        },
                        {
                            "log_type": "CCEL",
                            "log_data": "test_log"
                        }
                    ]
                }
            }"#
        ).unwrap()
    }

    /// # Returns
    /// * `Result<Value, PluginError>` - Returns verification result on success, or corresponding error on failure
    async fn verify_evidence(
        &self,
        user_id: &str,
        node_id: Option<&str>,
        evidence: &Value,
        nonce: Option<&[u8]>,
    ) -> Result<Value, PluginError> {
        let evidence_value = VritCCAEvidence::from_json_value(evidence)?;
        let result = evidence_value.verify(user_id, node_id, nonce, self).await?;
        Ok(result)
    }
}

#[no_mangle]
/// Creates a new plugin instance.
///
/// # Parameters
/// - `host_functions`: The service host functions.
/// - `plugin_type`: The type of the plugin as `&str`.
///
/// # Returns
/// A `Result` containing a boxed `dyn ServicePlugin` or an error.
pub fn create_plugin(host_functions: ServiceHostFunctions, plugin_type: &str) -> Result<Box<dyn ServicePlugin>, Box<dyn Error>> {
    if plugin_type != "virt_cca" {
        return Err(Box::new(PluginError::InputError("Invalid plugin type".to_string())));
    }
    Ok(Box::new(VirtCCAPlugin::new(plugin_type.to_string(), host_functions)))
}