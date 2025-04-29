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