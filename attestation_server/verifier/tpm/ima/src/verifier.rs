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
use plugin_manager::{ServicePlugin, PluginError, PluginBase, ServiceHostFunctions};
use tpm_common_verifier::{GenerateEvidence, Evidence, EvidenceResult, PcrValues, LogResult, Logs};
use crate::measurement_log::ImaLog;
use once_cell::sync::Lazy;
use async_trait::async_trait;
use std::error::Error;

/// TPM IMA verification plugin
pub struct TpmImaPlugin {
    plugin_type: String,
    service_host_functions: ServiceHostFunctions,
}

impl TpmImaPlugin {
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

/// Generate evidence for TPM ima verification
/// plugin need implement GenerateEvidence trait to parse and verify evidence.
/// Log format is different for different plugins, so we need to parse log data in each plugin.
/// Log format: (tpm ima plugin is ima log, encoded by base64)
/// "logs": [
///     {
///         "log_type": "tpm_ima",
///         "log_data": "base64 encoded log data"
///     }
/// ]
#[async_trait]
impl GenerateEvidence for TpmImaPlugin {
    async fn generate_evidence(
        &self,
        user_id: &str,
        logs: Option<&Vec<Logs>>,
        pcr_values: &mut PcrValues,
    ) -> Result<Value, PluginError> {
        let logs = match logs {
            Some(logs) => logs,
            None => {
                let log_result = LogResult {
                    log_status: "no_log".to_string(),
                    ref_value_match_status: "ignore".to_string(),
                    log_type: "tpm_ima".to_string(),
                    log_data: None,
                };
                let evidence_result = EvidenceResult::new(vec![log_result], pcr_values.clone());
                let result: Value = evidence_result.to_json_value();
                return Ok(result);
            }
        };

        let log_data = logs.first().ok_or_else(|| PluginError::InputError("Failed to get log data".to_string()))?;
        if log_data.log_type != "ImaLog" {
            return Err(PluginError::InputError("Log type is not ImaLog".to_string()));
        }
        let mut ima_log = ImaLog::new(&log_data.log_data, &pcr_values.hash_alg)?;
        let (replay_result, ref_value_result) = match ima_log.verify(pcr_values, &self.service_host_functions, user_id).await {
            Ok(res) => res,
            Err(_) => (false, false)
        };
        let ima_log_json = ima_log.to_json_value()?;
        
        let ref_value_match_result = if !replay_result {
            "ignore".to_string()
        } else if ref_value_result {
            "matched".to_string()
        } else {
            "unmatched".to_string()
        };

        let logs_json = vec![
            LogResult {
                log_type: log_data.log_type.clone(),
                log_data: Some(ima_log_json),
                log_status: if replay_result { "replay_success".to_string() } else { "replay_failure".to_string() },
                ref_value_match_status: ref_value_match_result,
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

impl PluginBase for TpmImaPlugin {    
    fn plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

static SAMPLE_OUTPUT: Lazy<Value> = Lazy::new(|| {
    serde_json::from_str(
        r#"{
            "evidence": {
                "log_type": "tpm_ima",
                "log_status": "replay_success",
                "ref_value_match_status": "matched",
                "pcrs": {
                    "hash_alg": "sha256",
                    "pcr_values": [
                        {
                            "pcr_index": 10,
                            "pcr_value": "be00517f0f1e46f33a39e0a2c21f8f0ae681c647be00517f0f1e46f33a39e0a2"
                        }
                    ]
                },
                "logs": [
                    {
                        "pcr_index": 10,
                        "template_hash": "be00517f0f1e46f33a39e0a2c21f8f0ae681c647",
                        "template_name": "ima-ng",
                        "file_hash_alg": "sha256",
                        "file_hash": "0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a",
                        "file_path": "boot_aggregate",
                        "ref_value_matched": true
                    }
                ]
            }
        }"#
    ).unwrap()
});

#[async_trait]
impl ServicePlugin for TpmImaPlugin {
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
pub fn create_plugin(host_functions: ServiceHostFunctions, plugin_type: &str) -> Result<Box<dyn ServicePlugin>, Box<dyn Error>> {
    if plugin_type != "tpm_ima" {
        return Err(Box::new(PluginError::InputError("Invalid plugin type".to_string())));
    }
    Ok(Box::new(TpmImaPlugin::new(plugin_type.to_string(), host_functions)))
}
