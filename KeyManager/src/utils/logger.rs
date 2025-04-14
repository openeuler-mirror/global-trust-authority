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
use crate::utils::env_setting_center::{Environment};

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

pub fn init_logger() -> Result<(), SetLoggerError> {
    let log_level = &Environment::global().log_level;
    let log_path = &Environment::global().log_path;

    let level = parse_level(&log_level);

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .target(Target::Stdout)
        .build();

    // Logging to log file.
    let root_appender = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .build(log_path)
        .unwrap();

    // Log Trace level output to file where trace is the default level
    // and the programmatically specified level to stdout.
    let config = Config::builder()
        .appender(Appender::builder().build("root_appender", Box::new(root_appender)))
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Info)))
                .build("stdout", Box::new(stdout)),
        )
        .build(
            Root::builder()
                .appender("root_appender")
                .appender("stdout")
                .build(level),
        )
        .unwrap();

    let _handle = log4rs::init_config(config)?;

    info!("init logger successfully");
    Ok(())
}
