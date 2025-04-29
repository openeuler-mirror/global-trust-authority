pub mod config;
pub mod logger;

use std::path::PathBuf;

static mut LOGGER: Option<logger::Logger> = None;

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
    let file = find_file("logging.yaml")
        .map(|path_buf| {
            let path = path_buf.to_str().unwrap();
            path.to_string()
        })
        .unwrap_or_else(|_| "logging.yaml".to_string());
    init_with_config(file)
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
///     common_log::init_with_config("logging.yaml").expect("Failed to initialize logger");
///     log::info!("Logger initialized");
/// }
/// ```
pub fn init_with_config(config_path: impl Into<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let logger = logger::Logger::new(config_path)?;
    unsafe {
        LOGGER = Some(logger);
    }
    Ok(())
}

// Re-export log macros for convenient use in other modules
use env_config_parse::find_file;
pub use log::{debug, error, info, trace, warn};
