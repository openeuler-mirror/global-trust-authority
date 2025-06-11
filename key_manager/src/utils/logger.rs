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
use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use crate::utils::env_setting_center::Environment;
use log::{LevelFilter, SetLoggerError, info};
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};

const LOG_PATTERN: &'static str = "{d(%Y-%m-%dT%H:%M:%S%.3f)} {P} [{l}] {t} - {m}{n}";

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

/// desc: init log config
/// 
/// # Arguments
/// 
/// * `enable_stdout` - if true, log will output to stdout
/// 
/// # Returns
/// 
/// * `Result<(), SetLoggerError>` - if success, return Ok(())
/// 
/// # Errors
/// 
/// * `SetLoggerError` - if failed, return Err(SetLoggerError)
pub fn init_logger(enable_stdout: bool) -> Result<(), SetLoggerError> {
    let log_level = &Environment::global().log_level;
    let log_path = &Environment::global().log_path;
    
    let log_dir = Path::new(log_path).parent().expect("log path could not get parent directory");
    fs::create_dir_all(log_dir).expect("log path create error");
    let dir_permissions = fs::Permissions::from_mode(0o750);
    fs::set_permissions(log_dir, dir_permissions).expect("log path permission set error");
    let level = parse_level(&log_level);

    // Logging to log file.
    let root_appender = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .build(log_path).expect("Unable to create logger appender");

    let file_permissions = fs::Permissions::from_mode(0o640); // 640 = rw-r-----
    fs::set_permissions(log_path, file_permissions).expect("log file permission set error");

    // Log Trace level output to file where trace is the default level
    // and the programmatically specified level to stdout.
    let mut config_builder = Config::builder()
        .appender(Appender::builder().build("root_appender", Box::new(root_appender)));
    let mut root_appenders = vec!["root_appender"];

    if enable_stdout {
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
            .target(Target::Stdout)
            .build();
        let stdout_appender = Appender::builder()
            .filter(Box::new(ThresholdFilter::new(LevelFilter::Info)))
            .build("stdout", Box::new(stdout));
        config_builder = config_builder.appender(stdout_appender);
        root_appenders.push("stdout");
    }
    let config = config_builder
        .build(Root::builder().appenders(root_appenders).build(level))
        .expect("Unable to create logger config");

    let _handle = log4rs::init_config(config)?;

    info!("init logger successfully");
    Ok(())
}
