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

use std::{env, sync};
use crate::config::config::{KEY_MANAGER_CERT_PATH, KEY_MANAGER_KEY_PATH, KEY_MANAGER_LOG_LEVEL, KEY_MANAGER_LOG_PATH, KEY_MANAGER_PORT, KEY_MANAGER_ROOT_TOKEN, KEY_MANAGER_SECRET_ADDR, ROOT_CA_CERT_PATH};
use crate::utils::errors::AppError;

pub fn load_env() -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    let bin_dir = if let Some(dir) = exe_path.parent() {
        dir
    } else {
        return Err("failed to get parent directory".into());
    };
    let env_path = bin_dir.join(".env");

    dotenv::from_path(env_path)?;

    Ok(())
}

#[derive(Debug)]
pub struct Environment {
    pub port : u16,
    pub cert: String,
    pub private_key: String,
    pub root_ca_cert: String,
    pub log_level : String,
    pub log_path : String,
    pub root_token: String,
    pub addr: String
}

pub static ENVIRONMENT_CONFIG: sync::OnceLock<Environment> = sync::OnceLock::new();

impl Environment {
    pub fn default() -> Self {
        Self {
            port : 0,
            cert: String::new(),
            private_key: String::new(),
            root_ca_cert: String::new(),
            log_level : String::new(),
            log_path : String::new(),
            root_token: String::new(),
            addr: String::new()
        }
    }

    /// desc: check .env config is existed
    pub fn check() -> Result<(), AppError> {
        get_port()?;
        get_cert()?;
        get_key()?;
        get_root_ca_cert()?;
        get_log_level()?;
        get_log_path()?;
        get_root_token()?;
        get_addr()?;
        Ok(())
    }

    /// desc: set env value to global static params 
    pub fn global() -> &'static Environment {
        ENVIRONMENT_CONFIG.get_or_init(|| {
            let mut environment = Environment::default();
            environment.port = get_port().expect("failed to get port number");
            environment.cert = get_cert().expect("failed to get cert string");
            environment.private_key = get_key().expect("failed to get private key string");
            environment.root_ca_cert = get_root_ca_cert().expect("failed to get root_ca_cert string");
            environment.log_level = get_log_level().expect("failed to get log level");
            environment.log_path = get_log_path().expect("failed to get log path");
            environment.root_token = get_root_token().expect("failed to get root_token string");
            environment.addr = get_addr().expect("failed to get addr string");
            environment
        })
    }
}

/// desc: get port from .env config
pub fn get_port() -> Result<u16, AppError> {
    let port_str = env::var(KEY_MANAGER_PORT).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_PORT)))?;
    let port = port_str.parse::<u16>().map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_PORT)))?;
    Ok(port)
}

/// desc: get cert path from .env config
pub fn get_cert() -> Result<String, AppError> {
    let cert = env::var(KEY_MANAGER_CERT_PATH).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_CERT_PATH)))?;
    Ok(cert)
}

/// desc: get private key path from .env config
pub fn get_key() -> Result<String, AppError> {
    let key = env::var(KEY_MANAGER_KEY_PATH).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_KEY_PATH)))?;
    Ok(key)
}

/// desc: get log level from .env config
pub fn get_log_level() -> Result<String, AppError> {
    let log_level = env::var(KEY_MANAGER_LOG_LEVEL).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_LOG_LEVEL)))?;
    Ok(log_level)
}

/// desc: get log path from .env config
pub fn get_log_path() -> Result<String, AppError> {
    let log_path = env::var(KEY_MANAGER_LOG_PATH).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_LOG_PATH)))?;
    Ok(log_path)
}

/// desc: get openbao root token from .env config
pub fn get_root_token() -> Result<String, AppError> {
    let root_token = env::var(KEY_MANAGER_ROOT_TOKEN).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_ROOT_TOKEN)))?;
    Ok(root_token)
}

/// desc: get openbao addr from .env config
pub fn get_addr() -> Result<String, AppError> {
    let addr = env::var(KEY_MANAGER_SECRET_ADDR).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_SECRET_ADDR)))?;
    Ok(addr)
}

/// desc: get root ca cert from .env config
pub fn get_root_ca_cert() -> Result<String, AppError> {
    let ca_cert = env::var(ROOT_CA_CERT_PATH).map_err(|_| AppError::EnvConfigError(String::from(ROOT_CA_CERT_PATH)))?;
    Ok(ca_cert)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use super::Environment;

    #[test]
    fn test_env_check() {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
        let config_path = test_dir.join(".env");
        let _ = dotenv::from_path(config_path);
        match Environment::check() {
            Ok(_) => {
                assert!(true);
            },
            Err(_err) => {
                assert!(false);
            }
        }
    }
}