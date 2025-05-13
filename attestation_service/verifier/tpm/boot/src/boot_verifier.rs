//! TPM Boot Verification Module
//!
//! This module implements the plugin functionality for TPM boot integrity verification,
//! responsible for parsing and verifying TPM event logs, and generating verification evidence.
//! This module is one of the core components of the integrity verification system,
//! implementing the conversion from TPM event logs to structured data for policy evaluation.
//!
//! Main features include:
//! - Implementing the ServicePlugin interface, providing functionality to create plugins,
//!   generate sample output, and verify evidence
//! - Implementing the GenerateEvidence interface, responsible for parsing TPM event logs
//!   and generating evidence
//! - Converting Base64-encoded event logs into structured JSON data
//! - Verifying PCR value consistency to ensure system boot integrity

use std::sync::Arc;
use std::sync::Mutex;
use serde_json::Value;
use plugin_manager::{ServicePlugin, PluginError, PluginBase, ServiceHostFunctions};
use tpm_common_verifier::{GenerateEvidence, Evidence, EvidenceResult, PcrValues, LogResult, Logs};
use crate::EventLog;
use async_trait::async_trait;

/// TPM Boot Verification Plugin
///
/// This struct implements TPM boot integrity verification functionality, connected to
/// the remote attestation system as a service plugin. It is responsible for parsing and
/// verifying TPM event logs, confirming the integrity of components measured during the system boot process.
///
/// # Fields
/// * `plugin_type` - Plugin type identifier, typically "tpm_boot"
/// * `service_host_functions` - Collection of functions provided by the host service,
///   used for interaction with the host service
pub struct TpmBootPlugin {
    plugin_type: String,
    service_host_functions: ServiceHostFunctions,
}

impl TpmBootPlugin {
    /// Creates a new instance of the TPM boot verification plugin
    ///
    /// # Parameters
    /// * `plugin_type` - Plugin type identifier
    /// * `service_host_functions` - Collection of functions provided by the host service
    ///
    /// # Returns
    /// * `Self` - Initialized TPM boot verification plugin instance
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

/// Generate evidence for TPM boot verification
///
/// Implements the GenerateEvidence trait to parse and verify evidence. Since different plugins
/// have different log formats, this is where different plugin implementations differ.
/// Each plugin needs to implement its own log parsing logic. The log format for the TPM boot
/// plugin is a Base64-encoded event log.
///
/// Example log format:
/// ```json
/// "logs": [
///     {
///         "log_type": "tpm_boot",
///         "log_data": "base64 encoded log data"
///     }
/// ]
/// ```
#[async_trait]
impl GenerateEvidence for TpmBootPlugin {
    /// Generate TPM boot verification evidence
    ///
    /// Parses TPM event logs and verifies PCR value matches, generating structured evidence data
    /// for policy evaluation.
    ///
    /// # Parameters
    /// * `_user_id` - User ID, not currently used
    /// * `logs` - List of log data, containing Base64-encoded TPM event logs
    /// * `pcr_values` - Collection of PCR values, used to verify the integrity of event logs
    ///
    /// # Returns
    /// * `Result<Value, PluginError>` - Returns evidence data in JSON format on success,
    ///   or corresponding error on failure
    async fn generate_evidence(
        &self,
        _user_id: &str,
        logs: &Vec<Logs>,
        pcr_values: &mut PcrValues
    ) -> Result<Value, PluginError> {
        // Check if logs is empty or has more than one log. Just support one log for now.
        if logs.is_empty() || logs.len() > 1 {
            return Err(PluginError::InputError("No logs found".to_string()));
        }

        let pcr_digest_algorithm: String = pcr_values.get_pcr_digest_algorithm();
        let log_data: &Logs = logs
            .first()
            .ok_or_else(|| PluginError::InputError("Failed to get log data".to_string()))?;
        if log_data.log_type != "TcgEventLog" {
            return Err(PluginError::InputError("Log type is not TcgEventLog".to_string()));
        }

        // Create thread-safe reference to PCR values
        let pcr_values_mutex = Arc::new(Mutex::new(pcr_values.clone()));

        // Parse event log
        let mut event_data = EventLog::new(&log_data.log_data);
        if let Err(e) = event_data
            .with_algorithm(pcr_digest_algorithm.as_str())
            .with_pcr_values(pcr_values_mutex.clone())
            .parse_event_log() {
            return Err(PluginError::InputError(format!("Failed to parse event log: {}", e)));
        }

        // Verify that event log matches PCR values
        let is_match: bool = event_data.verify()?;
        let event_log: Value = event_data.to_json_value()?;
        let updated_pcr_values = pcr_values_mutex.lock().unwrap().clone();

        // Generate result
        let logs_json: Vec<LogResult> = vec![
            LogResult {
                is_log_valid: is_match,
                log_type: log_data.log_type.clone(),
                log_data: event_log
            }
        ];
        let evidence_result = EvidenceResult::new(logs_json, updated_pcr_values);
        let result: Value = evidence_result.to_json_value();
        Ok(result)
    }

    /// Get host service functions
    ///
    /// # Returns
    /// * `&ServiceHostFunctions` - Reference to host service functions
    fn get_host_functions(&self) -> &ServiceHostFunctions {
        &self.service_host_functions
    }

    fn get_plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

impl PluginBase for TpmBootPlugin {
    /// Get plugin type
    ///
    /// # Returns
    /// * `&str` - Plugin type string
    fn plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

#[async_trait]
impl ServicePlugin for TpmBootPlugin {
    /// Get sample output
    ///
    /// Provides a sample evidence output format, used when importing policy files
    /// to check if the policy file format is correct
    ///
    /// # Returns
    /// * `Value` - Sample evidence data in JSON format
    fn get_sample_output(&self) -> Value {
        serde_json::from_str(
            r#"{
                "evidence": {
                    "is_log_valid": true,
                    "logs": [
                        {
                            "log_type": "tpm_boot",
                            "log_data": [
                                {
                                    "event_number": 5,
                                    "pcr_index": 7,
                                    "event_type": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                                    "digest": {
                                        "hash_id": "sha256",
                                        "digest": "115aa827dbccfb44d216ad9ecfda56bdea620b860a94bed5b7a27bba1c4d02d8"
                                    },
                                    "event": {
                                        "variable_name": "8be4df61-93ca-11d2-aa0d-00e098032b8c",
                                        "unicode_name": "SecureBoot",
                                        "variable_data": {
                                            "SecureBoot": {
                                                "enabled": "No"
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    ],
                    "pcrs": {
                        "hash_alg": "sha256",
                        "pcr_values": [
                            {
                                "is_matched": true,
                                "pcr_index": 0,
                                "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35",
                                "replay_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35"
                            },
                            {
                                "is_matched": true,
                                "pcr_index": 1,
                                "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be",
                                "replay_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be"
                            },
                            {
                                "is_matched": null,
                                "pcr_index": 2,
                                "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                                "replay_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                            },
                            {
                                "is_matched": true,
                                "pcr_index": 3,
                                "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                                "replay_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                            }
                        ]
                    }
                }
            }"#
        ).unwrap()
    }

    /// Verify evidence
    ///
    /// Verifies the provided evidence data, checking its integrity and validity. Different plugins
    /// use the same verification logic, with differentiated processing in the generate_evidence function.
    /// Different plugins need to implement their own generate_evidence function, while this uses a unified
    /// verification logic.
    ///
    /// # Parameters
    /// * `user_id` - User ID
    /// * `node_id` - Node ID, optional
    /// * `evidence` - Evidence data to verify
    /// * `nonce` - Random number, optional, used to prevent replay attacks
    ///
    /// # Returns
    /// * `Result<Value, PluginError>` - Returns verification result on success, or corresponding error on failure
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

/// Create plugin instance
///
/// Called when dynamically loading the library to create a TPM boot verification plugin instance
///
/// # Parameters
/// * `host_functions` - Collection of functions provided by the host service
/// * `plugin_type` - Plugin type identifier
///
/// # Returns
/// * `Option<Box<dyn ServicePlugin>>` - Returns plugin instance on success, None if type doesn't match
#[no_mangle]
pub fn create_plugin(host_functions: ServiceHostFunctions, plugin_type: &str) -> Option<Box<dyn ServicePlugin>> {
    if plugin_type != "tpm_boot" {
        return None;
    }
    Some(Box::new(TpmBootPlugin::new(plugin_type.to_string(), host_functions)))
}
