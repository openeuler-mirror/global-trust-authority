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

pub mod config;
pub mod logger;

use std::{path::PathBuf, sync::OnceLock};

static LOGGER: OnceLock<logger::Logger> = OnceLock::new();

/// Initialize logging system using default configuration file path "logging.yaml"
///
/// # Example
/// ```
///
/// fn main() {
///     common_log::init().expect("Failed to initialize logger");
///     log::info!("Logger initialized");
/// }
/// ```
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    init_with_yaml("logging.yaml")
}

pub fn init_docker() -> Result<(), Box<dyn std::error::Error>> {
    let file = find_file("logging.yaml")
        .map(|path_buf| {
            let path = path_buf.to_str().unwrap();
            path.to_string()
        }).expect(&format!("Failed to find logging file: logging.yaml"));
    init_with_yaml(file)
}

pub fn init_rpm() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(debug_assertions))]
    {
        let file = String::from("/etc/attestation_server/logging.yaml");
        init_with_yaml(file)
    }
    #[cfg(debug_assertions)]
    {
        let file = find_file("logging.yaml")
            .map(|path_buf| {
                let path = path_buf.to_str().unwrap();
                path.to_string()
            })
            .unwrap_or_else(|_| "logging.yaml".to_string());
        init_with_yaml(file)
    }
}


/// Initialize logging system
///
/// # Arguments
/// * `config_path` - Path to the logging configuration file
///
/// # Example
/// ```
///
/// fn main() {
///     common_log::init_with_yaml("logging.yaml").expect("Failed to initialize logger");
///     log::info!("Logger initialized");
/// }
/// ```
pub fn init_with_yaml(config_path: impl Into<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let logger = logger::Logger::new_from_yaml(config_path)?;
    if LOGGER.set(logger).is_err() {
        return Err("Logger already initialized".into());
    }
    Ok(())
}

/// Initialize logging system with config
///
/// # Arguments
/// * `config` - LogConfig info
///
/// # Example
/// ```
///
/// fn main() {
///     use common_log::config::LoggerConfig;
///     use common_log::init_with_config;
///     let mut loggers = Vec::new();
///     let log = LoggerConfig {
///                 path_prefix: "root".to_string(),
///                 log_directory: "logs".to_string(),
///                 log_file_name: "root-ra.log".to_string(),
///                 max_file_size: 10480,
///                 max_zip_count: 6,
///                 level: "info".to_string(),
///     };
///     loggers.push(log);
///     let config = LogConfig {
///         loggers
///         };
///    init_with_config(config).expect("Failed to initialize logger");
///    log::info!("Logger initialized");
/// }
/// ```

pub fn init_with_config(config: LogConfig) -> Result<(), Box<dyn std::error::Error>> {
    let logger = logger::Logger::new_from_config(config)?;
    if LOGGER.set(logger).is_err() {
        return Err("Logger already initialized".into());
    }
    Ok(())
}

// Re-export log macros for convenient use in other modules
use env_config_parse::find_file;
pub use log::{debug, error, info, trace, warn};
use crate::config::LogConfig;
