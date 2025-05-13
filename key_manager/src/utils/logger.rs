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

pub fn init_logger(enable_stdout: bool) -> Result<(), SetLoggerError> {
    let log_level = &Environment::global().log_level;
    let log_path = &Environment::global().log_path;

    let level = parse_level(&log_level);

    // Logging to log file.
    let root_appender = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .build(log_path)
        .unwrap();

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
        .unwrap();

    let _handle = log4rs::init_config(config)?;

    info!("init logger successfully");
    Ok(())
}
