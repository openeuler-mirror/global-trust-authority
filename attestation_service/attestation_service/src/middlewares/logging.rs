use log::info;
use common_log::init;

/// init logger
pub fn init_logger() {
    init().expect("Failed to initialize logger");
    info!("Logger initialized");
}