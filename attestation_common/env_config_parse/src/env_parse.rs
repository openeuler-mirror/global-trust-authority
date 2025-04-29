use std::env;
use log::{error, info};

pub async fn get_pod_name() -> String {
    get_env_value("POD_NAME").await
}

pub async fn get_env_value(key: &str) -> String {
    info!("will be get values for key {}", key);
    match env::var(key) {
        Ok(value) => value.to_string(),
        Err(e) => {
            error!("Failed to get environment variable {}: {:?}", key, e);
            String::new() // Returns a default value, such as an empty string.
        }
    }
}