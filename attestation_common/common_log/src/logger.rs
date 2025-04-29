use chrono::{DateTime, Local};
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
use std::path::PathBuf;
use crate::config::{LogConfig, LoggerConfig};

pub struct Logger {
    handle: Handle,
}

impl Logger {
    pub fn new(config_path: impl Into<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let config = LogConfig::from_yaml(config_path)?;
        let mut log4rs_config = Config::builder();

        // Create appenders for each logger configuration
        for logger_config in &config.loggers {
            let appender = Self::create_appender(logger_config)?;
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
            let root_appender = Self::create_appender(root_config)?;
            // Check if root_appender exists, add if not
            if !root_appender_exists {
                log4rs_config = log4rs_config.appender(
                    Appender::builder().build(root_appender_name, Box::new(root_appender)),
                );
            }

            let log_out_dir = env::var("LOG_OUTPUT_DIR").expect("LOG_OUTPUT_DIR must be set");
            let relative_log_directory = format!("{}/logs", log_out_dir);

            std::fs::create_dir_all(&relative_log_directory)?;

            // scan zip file
            let zip_files: Vec<_> = std::fs::read_dir(&relative_log_directory)?
                .filter_map(|entry| {
                    let path = entry.ok().unwrap().path();
                    if path.is_file() && path.extension().map_or(false, |ext| ext == "zip") {
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
        Ok(Self { handle })
    }

    fn create_appender(
        config: &LoggerConfig,
    ) -> Result<RollingFileAppender, Box<dyn std::error::Error>> {
        match dotenv::dotenv() {
            Ok(path) => info!("load .env file: {}", path.display()),
            Err(e) => error!(".env load fail: {}", e),
        }
        let log_out_dir = env::var("LOG_OUTPUT_DIR").expect("LOG_OUTPUT_DIR must be set");
        let relative_log_directory = format!("{}/{}", log_out_dir, config.log_directory);

        // Create log directory
        std::fs::create_dir_all(&relative_log_directory)?;

        // Get current local time
        let now: DateTime<Local> = Local::now();
        let formatted_time = now.format("%Y%m%d%H%M%S%3f").to_string();

        // Configure log file path
        let log_file = format!("{}/{}", relative_log_directory, config.log_file_name);
        let archived_log_pattern = format!(
            "{}/{}-{{}}-{}.zip",
            relative_log_directory, config.log_file_name, formatted_time
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
            .build(log_file, Box::new(compound_policy))?;

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
