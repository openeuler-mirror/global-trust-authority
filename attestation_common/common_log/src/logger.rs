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

use log::{error, info, LevelFilter};
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger as SizeBasedTriggerPolicy;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::{
    append::rolling_file::RollingFileAppender,
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
    Config, Handle,
};
use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use crate::config::{LogConfig, LoggerConfig};

#[allow(dead_code)]
pub struct Logger {
    handle: Handle,
}

impl Logger {
    pub fn new_from_config(config: LogConfig) -> Result<Self, Box<dyn Error>> {
        Self::new_without_env(config)
    }

    pub fn new_from_yaml(config_path: impl Into<PathBuf>) -> Result<Self, Box<dyn Error>> {
        let config = LogConfig::from_yaml(config_path)?;
        Self::new(config)
    }

    fn spawn_permission_monitor(config: Option<LoggerConfig>) {
        let (relative_log_directory, root_log_file) = match config {
            Some(root_config) => {
                let root_log_file = std::path::Path::new(&root_config.log_directory)
                    .join(root_config.log_file_name.as_str());
                (root_config.log_directory, root_log_file)
            },
            None => {
                let log_out_dir = env::var("LOG_OUTPUT_DIR").expect("LOG_OUTPUT_DIR must be set");
                let log_directory = std::path::Path::new(&log_out_dir).join("logs").to_string_lossy().to_string();
                let root_log_file = std::path::Path::new(&log_directory).join("root.log");
                (log_directory, root_log_file)
            },
        };

        std::thread::spawn(move || {
            loop {
                if let Ok(metadata) = std::fs::metadata(&root_log_file) {
                    if metadata.is_file() {
                        let permissions = Permissions::from_mode(0o640);
                        if let Err(e) = std::fs::set_permissions(&root_log_file, permissions) {
                            error!("Failed to set root log file permissions: {}", e);
                        }
                    }
                }
                // Set zip file permissions to 440 (owner r, group r, others none)
                if let Ok(entries) = std::fs::read_dir(&relative_log_directory) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_file() && path.extension().map_or(false, |ext| ext == "gz") {
                            let permissions = Permissions::from_mode(0o440);
                            if let Err(e) = std::fs::set_permissions(&path, permissions) {
                                error!("Failed to set zip file permissions for {}: {}", path.display(), e);
                            }
                        }
                    }
                }

                // Sleep for a period before checking again
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        });
    }

    /// Creates a new logger instance without using environment variables.
    ///
    /// This method has the following characteristics:
    /// 1. Does not use environment variables to set log paths, instead uses the paths directly from config
    /// 2. Does not create log directories, assumes they already exist
    /// 3. Controls permissions for log directories (750: owner rwx, group rx, others none)
    /// 4. Controls permissions for log files (640: owner rw, group r, others none)
    /// 5. Does not delete old compressed log files
    ///
    /// # Arguments
    ///
    /// * `config` - The logging configuration
    ///
    /// # Returns
    ///
    /// * `Result<Self, Box<dyn Error>>` - The logger instance or an error
    pub fn new_without_env(config: LogConfig) -> Result<Self, Box<dyn Error>> {
        let mut log4rs_config = Config::builder();
        for logger_config in &config.loggers {
            let appender = Self::create_appender(logger_config, logger_config.log_directory.as_str())?;
            let appender_name = format!("{}_appender", logger_config.path_prefix);
            log4rs_config = log4rs_config
                .appender(Appender::builder().build(&appender_name, Box::new(appender)));
            let logger = log4rs::config::Logger::builder()
                .appender(appender_name)
                .additive(false)
                .build(
                    logger_config.path_prefix.clone(),
                    Self::parse_level(&logger_config.level),
                );
            log4rs_config = log4rs_config.logger(logger);
        }

        // Configure root logger
        let final_config: Config;
        let root_appender_name = "root_appender";
        let root_appender_exists = config
            .loggers
            .iter()
            .any(|l| format!("{}_appender", l.path_prefix) == root_appender_name);

        if let Some(root_config) = config.get_root_config() {
            let root_appender = Self::create_appender(root_config, root_config.log_directory.as_str())?;
            if !root_appender_exists {
                log4rs_config = log4rs_config.appender(
                    Appender::builder().build(root_appender_name, Box::new(root_appender)),
                );
            }

            let root = Root::builder()
                .appender(root_appender_name)
                .build(Self::parse_level(&root_config.level));
            final_config = log4rs_config.build(root)?;
        } else {
            let root = Root::builder().build(LevelFilter::Info);
            final_config = log4rs_config.build(root)?;
        }
        let handle = log4rs::init_config(final_config)?;

        if let Some(root_config) = config.get_root_config().cloned() {
            Self::spawn_permission_monitor(Some(root_config));
        }

        Ok(Self { handle })
    }

    pub fn new(config: LogConfig) -> Result<Self, Box<dyn Error>> {
        let mut log4rs_config = Config::builder();

        // Create appenders for each logger configuration
        for logger_config in &config.loggers {
            let relative_log_directory = Self::get_relative_log_directory(logger_config)?;
            let appender = Self::create_appender(logger_config, &relative_log_directory)?;
            let appender_name = format!("{}_appender", logger_config.path_prefix);
            log4rs_config = log4rs_config
                .appender(Appender::builder().build(&appender_name, Box::new(appender)));

            // Add corresponding appender for each logger
            let logger = log4rs::config::Logger::builder()
                .appender(appender_name)
                .additive(false)
                .build(
                    logger_config.path_prefix.clone(),
                    Self::parse_level(&logger_config.level),
                );
            log4rs_config = log4rs_config.logger(logger);
        }

        // Configure root logger
        let final_config: Config;
        let root_appender_name = "root_appender";
        let root_appender_exists = config
            .loggers
            .iter()
            .any(|l| format!("{}_appender", l.path_prefix) == root_appender_name);

        if let Some(root_config) = config.get_root_config() {
            let relative_log_directory = Self::get_relative_log_directory(root_config)?;
            let root_appender = Self::create_appender(root_config, &relative_log_directory)?;
            // Check if root_appender exists, add if not
            if !root_appender_exists {
                log4rs_config = log4rs_config.appender(
                    Appender::builder().build(root_appender_name, Box::new(root_appender)),
                );
            }

            let log_out_dir = env::var("LOG_OUTPUT_DIR").expect("LOG_OUTPUT_DIR must be set");

            // Set LOG_OUTPUT_DIR permissions to 750 (owner rwx, group rx, others none)
            if let Ok(metadata) = std::fs::metadata(&log_out_dir) {
                if metadata.is_dir() {
                    let dir_permissions = Permissions::from_mode(0o750);
                    if let Err(e) = std::fs::set_permissions(&log_out_dir, dir_permissions) {
                        error!("Failed to set LOG_OUTPUT_DIR permissions: {}", e);
                    }
                }
            }

            let relative_log_directory = std::path::Path::new(&log_out_dir).join("logs").to_string_lossy().to_string();

            std::fs::create_dir_all(&relative_log_directory)?;

            // Set directory permissions to 750 (owner rwx, group rx, others none)
            let dir_permissions = Permissions::from_mode(0o750);
            if let Err(e) = std::fs::set_permissions(&relative_log_directory, dir_permissions) {
                error!("Failed to set log directory permissions: {}", e);
            }

            // scan zip file
            let zip_files: Vec<_> = std::fs::read_dir(&relative_log_directory)?
                .filter_map(|entry| {
                    let path = entry.ok().unwrap().path();
                    if path.is_file() && path.extension().map_or(false, |ext| ext == "gz") {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect();
            for path in zip_files.iter() {
                std::fs::remove_file(path).expect("delete log zip failed");
            }

            let root = Root::builder()
                .appender(root_appender_name)
                .build(Self::parse_level(&root_config.level));
            final_config = log4rs_config.build(root)?;
        } else {
            let root = Root::builder().build(LevelFilter::Info);
            final_config = log4rs_config.build(root)?;
        }

        let handle = log4rs::init_config(final_config)?;

        Self::spawn_permission_monitor(None);

        Ok(Self { handle })
    }

    fn get_relative_log_directory(
        config: &LoggerConfig,
    ) -> Result<String, Box<dyn Error>> {
        match dotenv::dotenv() {
            Ok(path) => info!("load .env file: {}", path.display()),
            Err(e) => error!(".env load fail: {}", e),
        }
        let log_out_dir = env::var("LOG_OUTPUT_DIR").expect("LOG_OUTPUT_DIR must be set");

        // Set LOG_OUTPUT_DIR permissions to 750 (owner rwx, group rx, others none)
        if let Ok(metadata) = std::fs::metadata(&log_out_dir) {
            if metadata.is_dir() {
                let dir_permissions = Permissions::from_mode(0o750);
                if let Err(e) = std::fs::set_permissions(&log_out_dir, dir_permissions) {
                    error!("Failed to set LOG_OUTPUT_DIR permissions: {}", e);
                }
            }
        }

        let relative_log_directory = std::path::Path::new(&log_out_dir).join(&config.log_directory).to_string_lossy().to_string();

        // Create log directory
        std::fs::create_dir_all(&relative_log_directory)?;

        // Set directory permissions to 750 (owner rwx, group rx, others none)
        let dir_permissions = Permissions::from_mode(0o750);
        if let Err(e) = std::fs::set_permissions(&relative_log_directory, dir_permissions) {
            error!("Failed to set log directory permissions: {}", e);
        }
        Ok(relative_log_directory)
    }

    fn create_appender(
        config: &LoggerConfig,
        relative_log_directory: &str,
    ) -> Result<RollingFileAppender, Box<dyn Error>> {
        // Configure log file path
        let log_file = std::path::Path::new(&relative_log_directory).join(&config.log_file_name).to_string_lossy().to_string();
        let archived_log_pattern = format!(
            "{}/{}-{{}}.gz",
            relative_log_directory, config.log_file_name
        );

        // Configure rolling policy
        let size_trigger = SizeBasedTriggerPolicy::new(config.max_file_size);
        let roller =
            FixedWindowRoller::builder().build(&archived_log_pattern, config.max_zip_count)?;
        let compound_policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(roller));

        // Create appender
        let appender = RollingFileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(
                "{d(%Y-%m-%d %H:%M:%S:%3f)} {l} [{M}:{L}] - {m}{n}",
            )))
            .build(log_file.clone(), Box::new(compound_policy))?;

        // Set file permissions to 640 (owner rw, group r, others none)
        if let Ok(metadata) = std::fs::metadata(&log_file) {
            if metadata.is_file() {
                let permissions = Permissions::from_mode(0o640);
                if let Err(e) = std::fs::set_permissions(&log_file, permissions) {
                    error!("Failed to set log file permissions: {}", e);
                }
            }
        }

        Ok(appender)
    }

    fn parse_level(level: &str) -> LevelFilter {
        match level.to_lowercase().as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            "off" => LevelFilter::Off,
            _ => LevelFilter::Info,
        }
    }
}
