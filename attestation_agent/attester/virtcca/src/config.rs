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


use plugin_manager::PluginError;

#[derive(Debug)]
pub struct VirtCCAConfig {
    pub plugin_type: String,
    pub ima_log_file_path: String,
    pub ccel_data_path: String,
}

impl VirtCCAConfig {
    pub fn from_json(plugin_type: String, config_json: &str) -> Result<Self, PluginError> {
        let config: serde_json::Value = serde_json::from_str(config_json)
            .map_err(|e| PluginError::InternalError(format!("Failed to parse plugin configuration as JSON: {}", e)))?;
        
        let ima_log_file_path = config
            .get("ima_log_file_path")
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let ccel_data_path = config
            .get("ccel_data_path")
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();

        Ok(Self {
            plugin_type,
            ima_log_file_path,
            ccel_data_path,
        })
    }
}