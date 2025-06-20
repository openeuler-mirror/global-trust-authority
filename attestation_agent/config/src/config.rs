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

use config_manager::ConfigSingleton;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashSet;
use std::path::PathBuf;

// refer to registry-of-reserved-tpm-2.0-handles-and-localites
const TPM_KEY_HANDLE_MIN: u32 = 0x81000000;
const TPM_KEY_HANDLE_MAX: u32 = 0x81FFFFFF;

// refer to registry-of-reserved-tpm-2.0-handles-and-localites
const TPM_NV_INDEX_MIN: u32 = 0x01000000;
const TPM_NV_INDEX_MAX: u32 = 0x01D1FFFF;

// Ak Cert Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AkCert {
    pub cert_type: String,
    pub ak_handle: Option<u32>,         // AK handle
    pub ak_nv_index: Option<u32>,       // AK NV index
}

// TPM Basic Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TpmBaseConfig {
    pub tcti_config: String,                                  // TCTI configuration string
    pub ak_certs: Vec<AkCert>,                                // AK cert arrary
    pub pcr_selections: Option<PcrSelection>,                 // PCR selection list
    pub quote_signature_scheme: Option<QuoteSignatureScheme>, // Quote signature scheme
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuoteSignatureScheme {
    pub signature_alg: String,
    pub hash_alg: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PcrSelection {
    pub banks: Vec<u32>,
    pub hash_alg: String,
}

// TPM Plugin Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TpmConfig {
    #[serde(flatten)]
    pub tpm_base: TpmBaseConfig, // Contains basic TPM configuration
    pub log_file_path: String, // Event log path
}

// IMA Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImaConfig {
    #[serde(flatten)]
    pub tpm_base: TpmBaseConfig, // Contains basic TPM configuration
    pub log_file_path: String,         // IMA log path
    pub template_name: Option<String>, // IMA template name
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "attester_type")]
pub enum PluginParams {
    #[serde(rename = "tpm_boot")]
    TpmBoot(TpmConfig),
    #[serde(rename = "tpm_ima")]
    TpmIma(ImaConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginConfig {
    pub name: String,
    pub policy_id: Vec<String>,
    pub path: String,
    pub enabled: bool,
    pub params: Option<PluginParams>,
}

// Initial Random Delay Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InitialDelayConfig {
    pub min_seconds: u64, // Minimum delay in seconds
    pub max_seconds: u64, // Maximum delay in seconds
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SchedulerConfig {
    pub name: String,                              // challenge...
    pub retry_enabled: bool,                       // Whether to retry the task
    pub intervals: u64,                            // Time interval for next scheduling, units: seconds
    pub initial_delay: Option<InitialDelayConfig>, // Optional startup delay configuration
    pub max_retries: Option<usize>,                // Optional maximum retries
    pub enabled: bool,                             // Whether to enable scheduler
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub server_url: String,
    pub tls: Option<TlsConfig>, // Optional TLS configuration, tls must be set if server_url start with 'https'.
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub uuid: Option<String>,    // Optional UUID to uniquely identify the agent
    pub user_id: Option<String>, // Optional use_id to uniquely identify the user
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub agent: AgentConfig,
    pub server: ServerConfig,
    pub plugins: Vec<PluginConfig>,
    pub schedulers: Vec<SchedulerConfig>,
    pub logging: LoggingConfig,
}

impl Config {
    /// Validates the configuration for the agent, server, plugins, schedulers, and logging.
    ///
    /// # Errors
    ///
    /// Returns an error string if any configuration is invalid, such as invalid log level, empty server URL,
    /// invalid plugin or scheduler configuration, etc.
    pub fn validate(&self) -> Result<(), String> {
        // 1. Validate logging configuration
        if !["trace", "debug", "info", "warn", "error"].contains(&self.logging.level.as_str()) {
            return Err(format!("Invalid log level: {}", self.logging.level));
        }

        // 2. Validate agent configuration
        if self.agent.listen_port == 0 {
            return Err("Invalid listen port: cannot be 0".to_string());
        }

        // 3. Validate server configuration
        if self.server.server_url.is_empty() {
            return Err("Server URL cannot be empty".to_string());
        }

        // 4. Validate plugin configuration
        for (idx, plugin) in self.plugins.iter().enumerate() {
            self.validate_plugin(plugin, idx)?;
        }

        // 5. Validate scheduler configuration
        for (idx, scheduler) in self.schedulers.iter().enumerate() {
            // Validate name
            if scheduler.name.is_empty() {
                return Err(format!("Scheduler #{} must have a name", idx));
            }

            // Validate initial delay (if present)
            if let Some(delay) = &scheduler.initial_delay {
                if delay.min_seconds > delay.max_seconds {
                    return Err(format!(
                        "Scheduler #{} '{}' has minimum delay({}) greater than maximum delay({})",
                        idx, scheduler.name, delay.min_seconds, delay.max_seconds
                    ));
                }
            }
        }

        // All validations passed
        Ok(())
    }

    /// Validates a single plugin configuration.
    ///
    /// # Errors
    ///
    /// Returns an error string if the plugin configuration is invalid, such as missing name, path, or invalid parameters.
    pub fn validate_plugin(&self, plugin: &PluginConfig, idx: usize) -> Result<(), String> {
        // Validate plugin name
        if plugin.name.is_empty() {
            return Err(format!("Plugin #{} must have a name", idx));
        }

        // Validate plugin path
        if plugin.path.is_empty() {
            return Err(format!("Plugin #{} '{}' must specify a path", idx, plugin.name));
        }

        // Validate policy_id limit
        if plugin.policy_id.len() > 10 {
            return Err(format!(
                "Plugin #{} '{}' has policy_id exceeding the limit of 10 (current: {})",
                idx,
                plugin.name,
                plugin.policy_id.len()
            ));
        }

        // Validate plugin parameters
        if let Some(params) = &plugin.params {
            match params {
                PluginParams::TpmBoot(config) => {
                    // Validate TPM base configuration
                    Self::validate_tpm_base_config(&config.tpm_base, &plugin.name, idx)?;
                },
                PluginParams::TpmIma(config) => {
                    // Validate TPM base configuration
                    Self::validate_tpm_base_config(&config.tpm_base, &plugin.name, idx)?;

                    // Validate IMA log path
                    if config.log_file_path.is_empty() {
                        return Err(format!("Plugin #{} '{}' IMA log path cannot be empty", idx, plugin.name));
                    }
                },
            }
        }

        Ok(())
    }

    /// Validate TPM base configuration
    fn validate_tpm_base_config(tpm_base: &TpmBaseConfig, plugin_name: &str, idx: usize) -> Result<(), String> {
        // Validate TCTI configuration
        let valid_tcti = ["device", "mssim", "swtpm", "tabrmd", "libtpm"];
        if !valid_tcti.contains(&tpm_base.tcti_config.as_str()) {
            return Err(format!(
                "Plugin #{} '{}' has invalid TCTI configuration: {}. Valid values: {:?}",
                idx, plugin_name, tpm_base.tcti_config, valid_tcti
            ));
        }

        // Validate AK certs
        let valid_cert_type = ["aik", "iak", "lak"];
        for (cert_idx, ak_cert) in tpm_base.ak_certs.iter().enumerate() {
            // Validate cert type
            if !valid_cert_type.contains(&ak_cert.cert_type.as_str()) {
                return Err(format!(
                    "Plugin #{} '{}' has invalid ak cert type at index {}: {}. Valid values: {:?}",
                    idx, plugin_name, cert_idx, ak_cert.cert_type, valid_cert_type
                ));
            }

            // Validate AK handle
            if let Some(handle) = ak_cert.ak_handle {
                if !(TPM_KEY_HANDLE_MIN..=TPM_KEY_HANDLE_MAX).contains(&handle) {
                    return Err(format!(
                        "Plugin #{} '{}' has AK handle value 0x{:x} at index {} outside valid range (0x{:x}-0x{:x})",
                        idx, plugin_name, handle, cert_idx, TPM_KEY_HANDLE_MIN, TPM_KEY_HANDLE_MAX
                    ));
                }
            }

            // Validate NV index
            if let Some(index) = ak_cert.ak_nv_index {
                if !(TPM_NV_INDEX_MIN..=TPM_NV_INDEX_MAX).contains(&index) {
                    return Err(format!(
                        "Plugin #{} '{}' has NV index value 0x{:x} at index {} outside valid range (0x{:x}-0x{:x})",
                        idx, plugin_name, index, cert_idx, TPM_NV_INDEX_MIN, TPM_NV_INDEX_MAX
                    ));
                }
            }
        }

        if tpm_base.ak_certs.is_empty() {
            return Err(format!("Plugin #{} '{}' No AK certificates found", idx, plugin_name));
        }

        // Check if LAK certificate exists, then IAK certificate must also exist
        if tpm_base.ak_certs.iter().any(|cert| cert.cert_type == "lak") {
            if !tpm_base.ak_certs.iter().any(|cert| cert.cert_type == "iak") {
                return Err(format!(
                    "Plugin #{} '{}' If LAK certificate exists, IAK certificate must also exist", idx, plugin_name
                ));
            }
        }
        // Validate PCR selections
        if let Some(pcr) = &tpm_base.pcr_selections {
            // Validate PCR indexes
            if pcr.banks.is_empty() {
                return Err(format!("Plugin #{} '{}' PCR banks cannot be empty", idx, plugin_name));
            }

            // Check for duplicate PCR indexes
            let mut pcr_set = HashSet::new();
            for &bank in &pcr.banks {
                if !pcr_set.insert(bank) {
                    return Err(format!("Plugin #{} '{}' has duplicate PCR index {}", idx, plugin_name, bank));
                }

                if bank > 23 {
                    return Err(format!(
                        "Plugin #{} '{}' has PCR index {} outside range (0-23)",
                        idx, plugin_name, bank
                    ));
                }
            }

            // Validate hash algorithm
            let valid_hash = ["sha1", "sha256", "sha384", "sha512", "sm3"];
            if !valid_hash.contains(&pcr.hash_alg.as_str()) {
                return Err(format!(
                    "Plugin #{} '{}' has invalid hash algorithm: {}. Valid values: {:?}",
                    idx, plugin_name, pcr.hash_alg, valid_hash
                ));
            }
        }

        // Validate signature scheme
        if let Some(scheme) = &tpm_base.quote_signature_scheme {
            // Validate signature algorithm
            let valid_sig = ["rsapss", "rsassa", "ecdsa"];
            if !valid_sig.contains(&scheme.signature_alg.as_str()) {
                return Err(format!(
                    "Plugin #{} '{}' has invalid signature algorithm: {}. Valid values: {:?}",
                    idx, plugin_name, scheme.signature_alg, valid_sig
                ));
            }

            // Validate hash algorithm
            let valid_hash = ["sha1", "sha256", "sha384", "sha512", "sm3"];
            if !valid_hash.contains(&scheme.hash_alg.as_str()) {
                return Err(format!(
                    "Plugin #{} '{}' has invalid hash algorithm: {}. Valid values: {:?}",
                    idx, plugin_name, scheme.hash_alg, valid_hash
                ));
            }
        }

        Ok(())
    }
}

/// Configuration manager that handles loading and accessing configuration settings
///
/// The configuration file is loaded using the following priority order:
/// 1. Command line specified path (if provided and the file exists)
/// 2. Current working directory: ./`agent_config.yaml`
/// 3. System-wide configuration: /`etc/attestation_agent/agent_config.yaml`
///
/// If no configuration file is found in any of these locations, an error is returned.
pub static AGENT_CONFIG: ConfigSingleton<Config> = ConfigSingleton::new();

#[derive(Clone)]
pub struct ConfigManager {
    config_path: String, // Records the actual configuration file path used
}

impl ConfigManager {
    /// Creates a new `ConfigManager` by loading and validating the configuration file from the given path.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration file cannot be found, loaded, or if the configuration is invalid.
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let actual_path = Self::find_config_path(config_path)?;

        AGENT_CONFIG.initialize(&actual_path).map_err(|e| format!("Failed to initialize config: {}", e))?;

        // Use simple validation method instead of complex validator validation
        AGENT_CONFIG.get_instance().and_then(|config| {
            config.validate().map_err(|e| format!("Configuration validation failed: {}", e))
        })?;

        Ok(Self { config_path: actual_path })
    }

    fn find_config_path(cli_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        // 1. Check command line specified path
        if !cli_path.is_empty() {
            let path = PathBuf::from(cli_path);
            if path.exists() {
                return Ok(cli_path.to_string());
            }
        }

        // 2. Check current working directory
        let current_dir_config = PathBuf::from("agent_config.yaml");
        if current_dir_config.exists() {
            return Ok(current_dir_config.to_string_lossy().to_string());
        }

        // 3. Check system-wide configuration directory
        let etc_config = PathBuf::from("/etc/attestation_agent/agent_config.yaml");
        if etc_config.exists() {
            return Ok(etc_config.to_string_lossy().to_string());
        }

        Err("Could not find configuration file. Tried command line path, current directory, and /etc directory.".into())
    }

    /// Get the actual path of the configuration file
    pub fn get_config_path(&self) -> &str {
        &self.config_path
    }

    /// Serializes any value that implements `serde::Serialize` to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error string if serialization fails.
    pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, String> {
        serde_json::to_string(value).map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }
}