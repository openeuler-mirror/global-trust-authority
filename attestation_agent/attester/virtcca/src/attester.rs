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
use std::fs::File;
use std::io::{BufReader, BufRead};

use base64::{engine::general_purpose, Engine as _};
use plugin_manager::{AgentPlugin, AgentHostFunctions, PluginBase, PluginError, QueryConfigurationFn};
use serde_json::Value;

use crate::config::VirtCCAConfig;
use crate::entity::{Log, VritCCAEvidence};
use crate::vcca_sdk::VccaSdk;

const MAX_IMA_LOG_LINES: usize = 100000;

/// Represents the VirtCCA plugin for attestation agents.
#[derive(Debug)]
pub struct VirtCCAPlugin {
    config: VirtCCAConfig,
}

impl VirtCCAPlugin {
    /// Creates a new instance of `VirtCCAPlugin`.
    ///
    /// # Parameters
    /// - `plugin_type`: The type of the plugin as a `String`.
    /// - `query_configuration`: Function to query plugin configuration.
    ///
    /// # Returns
    /// A `Result` containing the `VirtCCAPlugin` or a `PluginError`.
    pub fn new(plugin_type: String, query_configuration: QueryConfigurationFn) -> Result<Self, PluginError> {
        if plugin_type != "virt_cca" {
            return Err(PluginError::InputError("Invalid plugin type".to_string()));
        }
        let plugin_config = (query_configuration)(plugin_type.clone())
            .ok_or_else(|| PluginError::InternalError("Plugin configuration not found".to_string()))?;
        let config = VirtCCAConfig::from_json(plugin_type, &plugin_config)?;
        Ok(Self { config })
    }

    /// Collects logs of specified types.
    ///
    /// # Parameters
    /// - `log_type`: Optional vector of log types to collect.
    ///
    /// # Returns
    /// A `Result` containing optional vector of `Log` or a `PluginError`.
    pub fn collect_log(&self, log_type: Option<Vec<String>>) -> Result<Option<Vec<Log>>, PluginError> {
        let (is_collect_ima_log, is_collect_uefi_log) = match &log_type {
            None => (
                !self.config.ima_log_file_path.is_empty(),
                !self.config.ccel_data_path.is_empty()
            ),
            Some(types) if types.is_empty() => return Ok(None),
            Some(types) => {
                let mut ima = false;
                let mut uefi = false;
                
                for log_type in types {
                    match log_type.as_str() {
                        "ImaLog" => ima = true,
                        "CCEL" => uefi = true,
                        _ => return Err(PluginError::InternalError(format!("Invalid log type: {}", log_type)))
                    }
                }
                (ima, uefi)
            }
        };

        let mut logs = Vec::new();
        
        if is_collect_ima_log {
            logs.push(self.collect_ima_log()?);
        }
        
        if is_collect_uefi_log {
            logs.push(self.collect_uefi_log()?);
        }
        
        Ok(Some(logs))
    }

    fn collect_ima_log(&self) -> Result<Log, PluginError> {
        let ima_log_path = &self.config.ima_log_file_path;
        let file = std::fs::File::open(ima_log_path)
            .map_err(|e| PluginError::InternalError(format!("Failed to open IMA log file: {}", e)))?;
        let mut reader = BufReader::new(file);
        let mut line_count = 0;
        let mut buffer = Vec::new();

        let mut line = String::new();
        while reader.read_line(&mut line).map_err(|e| {
            PluginError::InternalError(format!("Failed to read IMA log file: {}", e))
        })? > 0 {
            line_count += 1;

            if line_count > MAX_IMA_LOG_LINES {
                return Err(PluginError::InternalError(
                    format!("IMA log file exceeds maximum allowed lines: {} > {}", line_count, MAX_IMA_LOG_LINES)
                ));
            }
            buffer.extend_from_slice(line.as_bytes());
            line.clear();
        }

        Ok(Log {
            log_type: "ImaLog".to_string(),
            log_data: general_purpose::STANDARD.encode(&buffer),
        })
    }

    fn collect_uefi_log(&self) -> Result<Log, PluginError> {
        let ccel_data_path = &self.config.ccel_data_path;

        // Open the boot log file
        let file = match File::open(ccel_data_path) {
            Ok(file) => file,
            Err(e) => return Err(PluginError::InternalError(format!("Failed to open log file: {}", e))),
        };

        // Check file size before reading
        let metadata = file.metadata().map_err(|e| {
            PluginError::InternalError(format!("Failed to get file metadata: {}", e))
        })?;

        // 5MiB = 5 * 1024 * 1024 bytes
        const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

        if metadata.len() > MAX_FILE_SIZE {
            return Err(PluginError::InternalError(
                format!("Log file size ({} bytes) exceeds maximum allowed size (5 MiB)",
                        metadata.len())
            ));
        }

        let ccel_data = std::fs::read(ccel_data_path)
            .map_err(|e| PluginError::InternalError(format!("Failed to read CCEL data file: {}", e)))?;
        Ok(Log {
            log_type: "CCEL".to_string(),
            log_data: general_purpose::STANDARD.encode(ccel_data),
        })
    }

    fn get_vcca_sdk(&self) -> Result<VccaSdk, PluginError> {
        VccaSdk::new().map_err(|e| PluginError::InternalError(format!("Failed to create VccaSdk: {}", e)))
    }

    fn generate_vcca_token_and_dev_cert(&self, nonce: Option<&[u8]>) -> Result<(String, String), PluginError> {
        let vcca_sdk = self.get_vcca_sdk()?;
        let challenge = match nonce {
            Some(n) => n.to_vec(),
            None => vec![0u8; 64],
        };

        fn retry<T, F>(mut f: F, desc: &str) -> Result<T, PluginError>
        where
            F: FnMut() -> Result<T, PluginError>,
        {
            let mut last_err: Option<PluginError> = None;
            for _ in 0..3 {
                match f() {
                    Ok(v) => return Ok(v),
                    Err(e) => last_err = Some(e),
                }
            }
            let msg = last_err.map(|e| e.to_string()).unwrap_or_else(|| "unknown error".to_string());
            Err(PluginError::InternalError(format!("{} after 3 attempts: {}", desc, msg)))
        }

        let token = retry(|| vcca_sdk.get_attestation_token(&challenge), "Failed to get attestation token")?;
        let dev_cert = retry(|| vcca_sdk.get_dev_cert(), "Failed to get device certificate")?;

        Ok((general_purpose::STANDARD.encode(&token), general_purpose::STANDARD.encode(&dev_cert)))
    }
}

impl PluginBase for VirtCCAPlugin {
    fn plugin_type(&self) -> &str {
        self.config.plugin_type.as_str()
    }
}

impl AgentPlugin for VirtCCAPlugin {
    // Collects evidence for attestation.
    fn collect_evidence(&self, _node_id: Option<&str>, nonce: Option<&[u8]>, log_type: Option<Vec<String>>) -> Result<Value, PluginError> {
        let logs = self.collect_log(log_type)?;

        let (vcca_token, dev_cert) = self.generate_vcca_token_and_dev_cert(nonce)?;

        let evidence = VritCCAEvidence {
            vcca_token,
            dev_cert,
            logs,
        };

        serde_json::to_value(evidence)
            .map_err(|e| PluginError::InternalError(format!("Failed to serialize evidence: {}", e)))
    }
}

/// Creates a new agent plugin instance.
///
/// # Parameters
/// - `host_functions`: Reference to agent host functions.
/// - `plugin_type`: The type of the plugin as `&str`.
///
/// # Returns
/// A `Result` containing a boxed `dyn AgentPlugin` or an error.
#[no_mangle]
pub fn create_plugin(host_functions: &AgentHostFunctions, plugin_type: &str) -> Result<Box<dyn AgentPlugin>, Box<dyn Error>> {
    let query_configuration = host_functions.query_configuration;
    VirtCCAPlugin::new(String::from(plugin_type), query_configuration)
        .map(|plugin| Box::new(plugin) as Box<dyn AgentPlugin>)
        .map_err(|e| Box::new(e) as Box<dyn Error>)
}
