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

use serde_json::Value;
use tpm_common_verifier::{GenerateEvidence, EvidenceResult, PcrValues, LogResult, Logs, Evidence};
use plugin_manager::{ServicePlugin, PluginError, PluginBase, ServiceHostFunctions};
use crate::dim_log::DimLog;
use once_cell::sync::Lazy;
use async_trait::async_trait;

/// TPM DIM verification plugin
pub struct TpmDimPlugin {
    plugin_type: String,
    service_host_functions: ServiceHostFunctions,
}

impl TpmDimPlugin {
    pub fn new(
        plugin_type: String,
        service_host_functions: ServiceHostFunctions
    ) -> Self {
        Self {
            plugin_type,
            service_host_functions,
        }
    }
}

/// Generate evidence for TPM dim verification
/// plugin need implement GenerateEvidence trait to parse and verify evidence.
/// Log format is different for different plugins, so we need to parse log data in each plugin.
/// Log format: (tpm dim plugin is dim log, encoded by base64)
/// "logs": [
///     {
///         "log_type": "tpm_dim",
///         "log_data": "base64 encoded log data"
///     }
/// ]
#[async_trait]
impl GenerateEvidence for TpmDimPlugin {
    async fn generate_evidence(
        &self,
        user_id: &str,
        logs: &Vec<Logs>,
        pcr_values: &mut PcrValues,
    ) -> Result<Value, PluginError> {
        // Check if logs is empty or has more than one log. Only support one log for now.
        if logs.is_empty() {
            return Err(PluginError::InputError("No log data provided".to_string()));
        }
        if logs.len() > 1 {
            return Err(PluginError::InputError("Multiple logs are not supported. Only one log is allowed.".to_string()));
        }

        let log_data = logs.first().ok_or_else(|| 
            PluginError::InputError("Failed to get log data: log entry is missing".to_string())
        )?;

        if log_data.log_type != "tpm_dim" {
            return Err(PluginError::InputError(
                format!("Invalid log type: expected 'tpm_dim', got '{}'", log_data.log_type)
            ));
        }

        let mut dim_log = DimLog::new(&log_data.log_data).map_err(|e| 
            PluginError::InputError(format!("Failed to parse DIM log: {:?}", e))
        )?;

        let is_log_valid = dim_log.verify(pcr_values, &self.service_host_functions, user_id)
            .await
            .map_err(|e| PluginError::InputError(format!("Failed to verify DIM log: {:?}", e)))?;

        let dim_log_json = dim_log.to_json_value().map_err(|e| 
            PluginError::InputError(format!("Failed to convert DIM log to JSON: {:?}", e))
        )?;

        let logs_json = vec![
            LogResult {
                log_type: log_data.log_type.clone(),
                log_data: dim_log_json,
                is_log_valid,
            }
        ];

        let evidence_result = EvidenceResult::new(logs_json, pcr_values.clone());
        let result = evidence_result.to_json_value();
        Ok(result)
    }

    fn get_host_functions(&self) -> &ServiceHostFunctions {
        &self.service_host_functions
    }

    fn get_plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

impl PluginBase for TpmDimPlugin {    
    fn plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

static SAMPLE_OUTPUT: Lazy<Value> = Lazy::new(|| {
    serde_json::from_str(
        r#"{
            "evidence": {
                "log_type": "tpm_dim",
                "is_log_valid": true,
                "pcrs": {
                    "hash_alg": "sha256",
                    "pcr_values": [
                        {
                            "is_matched": true,
                            "pcr_index": 12,
                            "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                            "replay_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                        }
                    ]
                },
                "logs": [
                    {
                        "pcr_index": 12,
                        "template_hash": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                        "file_hash_alg": "sha256",
                        "file_hash": "2f4a1a7c4b8e9d6f3c2a1b8e7d6f5c4b3a2e1d8c7b6f5e4d3c2b1a8e7d6f5c4b",
                        "file_path": "/usr/bin/systemd",
                        "log_type": "kernel"
                    }
                ]
            }
        }"#
    ).unwrap()
});

#[async_trait]
impl ServicePlugin for TpmDimPlugin {
    fn get_sample_output(&self) -> Value {
        SAMPLE_OUTPUT.clone()
    }

    async fn verify_evidence(
        &self,
        user_id: &str,
        node_id: Option<&str>,
        evidence: &Value,
        nonce: Option<&[u8]>
    ) -> Result<Value, PluginError> {
        let mut evidence_value = Evidence::from_json_value(evidence)?;
        let result = evidence_value.verify(user_id, node_id, nonce, self).await?;
        Ok(result)
    }
}

#[no_mangle]
pub fn create_plugin(host_functions: ServiceHostFunctions, plugin_type: &str) -> Option<Box<dyn ServicePlugin>> {
    if plugin_type != "tpm_dim" {
        return None;
    }
    Some(Box::new(TpmDimPlugin::new(plugin_type.to_string(), host_functions)))
} 