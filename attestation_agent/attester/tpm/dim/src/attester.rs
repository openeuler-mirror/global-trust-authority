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

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, error};
use plugin_manager::{AgentHostFunctions, AgentPlugin, PluginBase, PluginError, QueryConfigurationFn};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{BufRead, BufReader, Error as IoError};
use tpm_common_attester::{Log, TpmPluginBase, TpmPluginConfig};

const PLUGIN_TYPE: &str = "tpm_dim";
const MAX_LOG_LINES: usize = 100_000;
const DEFAULT_BUFFER_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Debug)]
pub struct TpmDimPlugin {
    config: TpmPluginConfig,
}

impl TpmDimPlugin {
    pub fn new(plugin_type: String, query_configuration: QueryConfigurationFn) -> Result<Self, PluginError> {
        if plugin_type != PLUGIN_TYPE {
            return Err(PluginError::InputError(format!("Invalid plugin type: {}", plugin_type)));
        }

        let plugin_config = query_configuration(plugin_type.clone())
            .ok_or_else(|| PluginError::InternalError("Plugin configuration not found".to_string()))?;

        let config = TpmPluginConfig::from_json(plugin_type, &plugin_config)?;
        Ok(Self { config })
    }

    fn collect_evidence_impl(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<Value, PluginError> {
        let logs = self.collect_log()?;

        Ok(json!({
            "node_id": node_id,
            "nonce": nonce.map(|n| STANDARD.encode(n)),
            "logs": logs,
        }))
    }

    fn read_log_file(&self) -> Result<Vec<u8>, PluginError> {
        let file = File::open(&self.config.log_file_path)
            .map_err(|e| self.handle_io_error("Failed to open DIM log file", e))?;

        let reader = BufReader::new(file);
        let mut line_count = 0;
        let mut buffer = Vec::with_capacity(DEFAULT_BUFFER_SIZE);

        for line in reader.lines() {
            let line = line.map_err(|e| self.handle_io_error("Failed to read DIM log file", e))?;

            line_count += 1;
            if line_count > MAX_LOG_LINES {
                return Err(PluginError::InputError(format!(
                    "DIM log exceeds maximum line limit of {} lines",
                    MAX_LOG_LINES
                )));
            }

            buffer.extend_from_slice(line.as_bytes());
            buffer.push(b'\n');
        }

        debug!("Successfully read {} lines from log file", line_count);
        Ok(buffer)
    }

    fn handle_io_error(&self, context: &str, error: IoError) -> PluginError {
        let error_msg = format!("{}: {}", context, error);
        error!("{}", error_msg);
        PluginError::InternalError(error_msg)
    }
}

impl PluginBase for TpmDimPlugin {
    fn plugin_type(&self) -> &str {
        self.config.plugin_type.as_str()
    }
}

impl AgentPlugin for TpmDimPlugin {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<Value, PluginError> {
        self.collect_evidence_impl(node_id, nonce)
    }
}

impl TpmPluginBase for TpmDimPlugin {
    fn config(&self) -> &TpmPluginConfig {
        &self.config
    }

    fn collect_log(&self) -> Result<Vec<Log>, PluginError> {
        let buffer = self.read_log_file()?;
        let log_data = STANDARD.encode(&buffer);

        Ok(vec![Log { log_type: PLUGIN_TYPE.to_string(), log_data }])
    }
}

#[no_mangle]
pub fn create_plugin(host_functions: &AgentHostFunctions, plugin_type: &str) -> Option<Box<dyn AgentPlugin>> {
    let query_configuration = host_functions.query_configuration;

    match TpmDimPlugin::new(String::from(plugin_type), query_configuration) {
        Ok(plugin) => Some(Box::new(plugin)),
        Err(e) => {
            error!("Failed to create plugin: {}", e);
            None
        },
    }
}
