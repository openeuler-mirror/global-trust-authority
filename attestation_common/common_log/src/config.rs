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

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub loggers: Vec<LoggerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct LoggerConfig {
    pub path_prefix: String,
    pub log_directory: String,
    pub log_file_name: String,
    pub max_file_size: u64,
    pub max_zip_count: u32,
    pub level: String,
}

impl LogConfig {
    pub fn from_yaml(path: impl Into<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = std::fs::read_to_string(path.into())?;
        let config: LogConfig = serde_yaml::from_str(&config_str)?;
        Ok(config)
    }

    pub fn get_logger_config(&self, path_prefix: &str) -> Option<&LoggerConfig> {
        self.loggers.iter().find(|l| path_prefix.starts_with(&l.path_prefix))
    }

    pub fn get_root_config(&self) -> Option<&LoggerConfig> {
        self.get_logger_config("root")
    }
}