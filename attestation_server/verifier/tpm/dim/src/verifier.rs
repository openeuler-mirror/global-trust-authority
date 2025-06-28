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

use crate::measurement_log::DimLog;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use plugin_manager::{PluginBase, PluginError, ServiceHostFunctions, ServicePlugin};
use serde_json::Value;
use tpm_common_verifier::{Evidence, EvidenceResult, GenerateEvidence, LogResult, Logs, PcrValues};

/// TPM DIM verification plugin
///
/// This plugin is responsible for verifying TPM DIM (Dynamic Integrity Measurement)
/// logs and PCR values. It implements the ServicePlugin and GenerateEvidence traits
/// to provide evidence generation and verification capabilities.
pub struct TpmDimPlugin {
    /// The type identifier for this plugin
    plugin_type: String,
    /// Host functions provided by the service for plugin operations
    service_host_functions: ServiceHostFunctions,
}

impl TpmDimPlugin {
    /// Creates a new instance of TpmDimPlugin
    ///
    /// # Arguments
    ///
    /// * `plugin_type` - The type identifier for this plugin
    /// * `service_host_functions` - Host functions provided by the service
    ///
    /// # Returns
    ///
    /// A new instance of TpmDimPlugin
    pub fn new(plugin_type: String, service_host_functions: ServiceHostFunctions) -> Self {
        Self { plugin_type, service_host_functions }
    }

    /// Validates the log data for TPM DIM verification
    ///
    /// # Arguments
    ///
    /// * `logs` - Vector of logs to validate
    ///
    /// # Returns
    ///
    /// Result containing the validated log data or an error
    fn validate_logs(logs: &[Logs]) -> Result<&Logs, PluginError> {
        if logs.is_empty() {
            return Err(PluginError::InputError("No log data provided".to_string()));
        }
        if logs.len() > 1 {
            return Err(PluginError::InputError(
                "Multiple logs are not supported. Only one log is allowed.".to_string(),
            ));
        }

        let log_data = logs
            .first()
            .ok_or_else(|| PluginError::InputError("Failed to get log data: log entry is missing".to_string()))?;

        if log_data.log_type != "tpm_dim" {
            return Err(PluginError::InputError(format!(
                "Invalid log type: expected 'tpm_dim', got '{}'",
                log_data.log_type
            )));
        }

        Ok(log_data)
    }

    /// Processes the DIM log and generates evidence
    ///
    /// # Arguments
    ///
    /// * `log_data` - The log data to process
    /// * `pcr_values` - PCR values to verify against
    /// * `user_id` - User identifier for verification
    ///
    /// # Returns
    ///
    /// Result containing the generated evidence or an error
    async fn process_dim_log(
        &self,
        log_data: &Logs,
        pcr_values: &mut PcrValues,
        user_id: &str,
    ) -> Result<Value, PluginError> {
        let mut dim_log = DimLog::new(&log_data.log_data)
            .map_err(|e| PluginError::InputError(format!("Failed to parse DIM log: {:?}", e)))?;

        let is_log_valid = dim_log
            .verify(pcr_values, &self.service_host_functions, user_id)
            .await
            .map_err(|e| PluginError::InputError(format!("Failed to verify DIM log: {:?}", e)))?;

        let dim_log_json = dim_log
            .to_json_value()
            .map_err(|e| PluginError::InputError(format!("Failed to convert DIM log to JSON: {:?}", e)))?;

        let logs_json = vec![LogResult { log_type: log_data.log_type.clone(), log_data: dim_log_json, is_log_valid }];

        let evidence_result = EvidenceResult::new(logs_json, pcr_values.clone());
        Ok(evidence_result.to_json_value())
    }
}

/// Implementation of GenerateEvidence trait for TpmDimPlugin
#[async_trait]
impl GenerateEvidence for TpmDimPlugin {
    /// Generates evidence from the provided logs and PCR values
    ///
    /// # Arguments
    ///
    /// * `user_id` - User identifier for verification
    /// * `logs` - Vector of logs to process
    /// * `pcr_values` - PCR values to verify against
    ///
    /// # Returns
    ///
    /// Result containing the generated evidence or an error
    async fn generate_evidence(
        &self,
        user_id: &str,
        logs: &Vec<Logs>,
        pcr_values: &mut PcrValues,
    ) -> Result<Value, PluginError> {
        let log_data = Self::validate_logs(logs)?;
        self.process_dim_log(log_data, pcr_values, user_id).await
    }

    /// Returns the host functions for this plugin
    fn get_host_functions(&self) -> &ServiceHostFunctions {
        &self.service_host_functions
    }

    /// Returns the plugin type
    fn get_plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

/// Implementation of PluginBase trait for TpmDimPlugin
impl PluginBase for TpmDimPlugin {
    /// Returns the plugin type
    fn plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

/// Sample output for the plugin
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
        }"#,
    )
    .unwrap()
});

/// Implementation of ServicePlugin trait for TpmDimPlugin
#[async_trait]
impl ServicePlugin for TpmDimPlugin {
    /// Returns the sample output for this plugin
    fn get_sample_output(&self) -> Value {
        SAMPLE_OUTPUT.clone()
    }

    /// Verifies the evidence for a given user
    ///
    /// # Arguments
    ///
    /// * `user_id` - User identifier for verification
    /// * `node_id` - Optional node identifier
    /// * `evidence` - Evidence to verify
    /// * `nonce` - Optional nonce for verification
    ///
    /// # Returns
    ///
    /// Result containing the verification result or an error
    async fn verify_evidence(
        &self,
        user_id: &str,
        node_id: Option<&str>,
        evidence: &Value,
        nonce: Option<&[u8]>,
    ) -> Result<Value, PluginError> {
        let mut evidence_value = Evidence::from_json_value(evidence)?;
        let result = evidence_value.verify(user_id, node_id, nonce, self).await?;
        Ok(result)
    }
}

/// Creates a new plugin instance
///
/// # Arguments
///
/// * `host_functions` - Host functions provided by the service
/// * `plugin_type` - Type identifier for the plugin
///
/// # Returns
///
/// Option containing a boxed plugin instance if the type matches
#[no_mangle]
pub fn create_plugin(host_functions: ServiceHostFunctions, plugin_type: &str) -> Option<Box<dyn ServicePlugin>> {
    if plugin_type != "tpm_dim" {
        return None;
    }
    Some(Box::new(TpmDimPlugin::new(plugin_type.to_string(), host_functions)))
}
