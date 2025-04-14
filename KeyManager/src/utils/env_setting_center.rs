use std::{env, sync};
use crate::config::config::{KEY_MANAGER_CERT_PATH, KEY_MANAGER_KEY_PATH, KEY_MANAGER_LOG_LEVEL, KEY_MANAGER_LOG_PATH, KEY_MANAGER_PORT, KEY_MANAGER_ROOT_TOKEN, KEY_MANAGER_TLS};
use crate::utils::response::AppError;

pub fn load_env()  {
    dotenv::dotenv().ok();
}

#[derive(Debug)]
pub struct Environment {
    pub port : u16,
    pub tls: bool,
    pub tls_cert: String,
    pub tls_key: String,
    pub log_level : String,
    pub log_path : String,
    pub root_token: String
}

pub static ENVIRONMENT_CONFIG: sync::OnceLock<Environment> = sync::OnceLock::new();

impl Environment {
    pub fn default() -> Self {
        Self {
            port : 0,
            tls: false,
            tls_cert: String::new(),
            tls_key: String::new(),
            log_level : String::new(),
            log_path : String::new(),
            root_token: String::new()
        }
    }

    pub fn check() -> Result<(), AppError> {
        get_port()?;
        if get_tls()? {
            get_cert()?;
            get_key()?;
        }
        get_log_level()?;
        get_log_path()?;
        get_root_token()?;
        Ok(())
    }

    pub fn global() -> &'static Environment {
        ENVIRONMENT_CONFIG.get_or_init(|| {
            let mut environment = Environment::default();
            environment.port = get_port().unwrap();
            environment.tls = get_tls().unwrap();
            if environment.tls {
                environment.tls_cert = get_cert().unwrap();
                environment.tls_key = get_key().unwrap();
            }
            environment.log_level = get_log_level().unwrap();
            environment.log_path = get_log_path().unwrap();
            environment.root_token = get_root_token().unwrap();
            environment
        })
    }
}


pub fn get_port() -> Result<u16, AppError> {
    let port_str = env::var(KEY_MANAGER_PORT).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_PORT)))?;
    let port = port_str.parse::<u16>().map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_PORT)))?;
    Ok(port)
}

pub fn get_tls() -> Result<bool, AppError> {
    let tls_str = env::var(KEY_MANAGER_TLS).map_err(|_e| AppError::EnvConfigError(String::from(KEY_MANAGER_TLS)))?;
    let tls = tls_str.parse::<bool>().map_err(|_e| AppError::EnvConfigError(String::from(KEY_MANAGER_TLS)))?;
    Ok(tls)
}

pub fn get_cert() -> Result<String, AppError> {
    let cert = env::var(KEY_MANAGER_CERT_PATH).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_CERT_PATH)))?;
    Ok(cert)
}

pub fn get_key() -> Result<String, AppError> {
    let key = env::var(KEY_MANAGER_KEY_PATH).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_KEY_PATH)))?;
    Ok(key)
}

pub fn get_log_level() -> Result<String, AppError> {
    let log_level = env::var(KEY_MANAGER_LOG_LEVEL).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_LOG_LEVEL)))?;
    Ok(log_level)
}

pub fn get_log_path() -> Result<String, AppError> {
    let log_path = env::var(KEY_MANAGER_LOG_PATH).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_LOG_PATH)))?;
    Ok(log_path)
}

pub fn get_root_token() -> Result<String, AppError> {
    let root_token = env::var(KEY_MANAGER_ROOT_TOKEN).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_ROOT_TOKEN)))?;
    Ok(root_token)
}