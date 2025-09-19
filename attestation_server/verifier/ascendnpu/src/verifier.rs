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

use crate::evidence::AscendNpuEvidence;

/// Represents the AscendNPU plugin for verification services.
pub struct AscendNpuPlugin {
    plugin_type: String,
    service_host_functions: ServiceHostFunctions,
}

impl AscendNpuPlugin {
    /// Creates a new instance of `AscendNpuPlugin`.
    ///
    /// # Parameters
    /// - `plugin_type`: The type of the plugin as a `String`.
    /// - `service_host_functions`: The host functions for the service.
    ///
    /// # Returns
    /// A new `AscendNpuPlugin` instance.
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

impl PluginBase for AscendNpuPlugin {
    fn plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

#[async_trait]
impl ServicePlugin for AscendNpuPlugin {
    fn get_sample_output(&self) -> Value {
        serde_json::from_str(
            r#"{
                "evidence": {
                    "ak_cert": "base64(der)",
                    "quote": {
                        "quote_data": "base64(TPMS_ATTEST)",
                        "signature": "base64(TPMT_SIGNATURE)"
                    },
                    "pcrs": {
                        "hash_alg": "sha256",
                        "pcr_values": [
                            {
                                "pcr_index": 1,
                                "pcr_value": "hex(value)"
                            },
                            {
                                "pcr_index": 2,
                                "pcr_value": "hex(value)"
                            }
                        ]
                    },
                    "logs": [
                        {
                            "log_type": "boot_measurement",
                            "log_data": "base64(boot_measurement_binary)"
                        },
                        {
                            "log_type": "runtime_measurement",
                            "log_data": "base64(ima_log_binary)"
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
        let evidence_value = AscendNpuEvidence::from_json_value(evidence)?;
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
    if plugin_type != "ascend_npu" {
        return Err(Box::new(PluginError::InputError("Invalid plugin type".to_string())));
    }
    Ok(Box::new(AscendNpuPlugin::new(plugin_type.to_string(), host_functions)))
}