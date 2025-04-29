use serde_json::Value;
use plugin_manager::{ServicePlugin, PluginError, PluginBase, ServiceHostFunctions};
use tpm_common_verifier::{GenerateEvidence, Evidence, EvidenceResult, PcrValues, LogResult, Logs};
use crate::ima_log::ImaLog;
use once_cell::sync::Lazy;
use async_trait::async_trait;

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
        logs: &Vec<Logs>,
        pcr_values: &mut PcrValues,
    ) -> Result<Value, PluginError> {
        // Check if logs is empty or has more than one log. Only support one log for now.
        if logs.is_empty() || logs.len() > 1 {
            return Err(PluginError::InputError("Number of log object is not 1.".to_string()));
        }

        let log_data = logs.first().ok_or_else(|| PluginError::InputError("Failed to get log data".to_string()))?;
        if log_data.log_type != "ImaLog" {
            return Err(PluginError::InputError("Log type is not ImaLog".to_string()));
        }
        let mut ima_log = ImaLog::new(&log_data.log_data)?;
        let is_log_valid: bool = match ima_log.verify(pcr_values, &self.service_host_functions, user_id).await {
            Ok(_) => true,
            Err(_) => false
        };
        let ima_log_json = ima_log.to_json_value()?;
        let logs_json = vec![
            LogResult {
                log_type: log_data.log_type.clone(),
                log_data: ima_log_json,
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
                "is_log_valid": true,
                "pcrs": {
                    "hash_alg": "sha256",
                    "pcr_values": [
                        {
                            "is_matched": true,
                            "pcr_index": 10,
                            "pcr_value": "be00517f0f1e46f33a39e0a2c21f8f0ae681c647be00517f0f1e46f33a39e0a2",
                            "replay_value": "be00517f0f1e46f33a39e0a2c21f8f0ae681c647be00517f0f1e46f33a39e0a2"
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
pub fn create_plugin(host_functions: ServiceHostFunctions, plugin_type: &str) -> Option<Box<dyn ServicePlugin>> {
    if plugin_type != "tpm_ima" {
        return None;
    }
    Some(Box::new(TpmImaPlugin::new(plugin_type.to_string(), host_functions)))
}
