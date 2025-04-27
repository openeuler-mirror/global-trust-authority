use std::{env, sync};
use crate::config::config::{KEY_MANAGER_CERT_PATH, KEY_MANAGER_KEY_PATH, KEY_MANAGER_LOG_LEVEL, KEY_MANAGER_LOG_PATH, KEY_MANAGER_PORT, KEY_MANAGER_ROOT_TOKEN, KEY_MANAGER_SECRET_ADDR, ROOT_CA_CERT_PATH};
use crate::utils::errors::AppError;

pub fn load_env() -> Result<(), AppError> {
    let exe_path = match env::current_exe() {
        Ok(path) => path,
        Err(_) => {
            log::error!("load .env config error, load current dir error");
            return Err(AppError::EnvConfigError(String::new()));
        }
    };
    let bin_dir = match exe_path.parent() {
        Some(dir) => dir,
        None => {
            log::error!("load .env config error, get parent dir error");
            return Err(AppError::EnvConfigError(String::new()))
        },
    };
    let env_path = bin_dir.join(".env");
    match dotenv::from_path(env_path) {
        Ok(_) => {}
        Err(_) => {
            log::error!("load .env config error");
            return Err(AppError::EnvConfigError(String::new()))
        }
    }
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

    pub fn global() -> &'static Environment {
        ENVIRONMENT_CONFIG.get_or_init(|| {
            let mut environment = Environment::default();
            environment.port = get_port().unwrap();
            environment.cert = get_cert().unwrap();
            environment.private_key = get_key().unwrap();
            environment.root_ca_cert = get_root_ca_cert().unwrap();
            environment.log_level = get_log_level().unwrap();
            environment.log_path = get_log_path().unwrap();
            environment.root_token = get_root_token().unwrap();
            environment.addr = get_addr().unwrap();
            environment
        })
    }
}


pub fn get_port() -> Result<u16, AppError> {
    let port_str = env::var(KEY_MANAGER_PORT).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_PORT)))?;
    let port = port_str.parse::<u16>().map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_PORT)))?;
    Ok(port)
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

pub fn get_addr() -> Result<String, AppError> {
    let addr = env::var(KEY_MANAGER_SECRET_ADDR).map_err(|_| AppError::EnvConfigError(String::from(KEY_MANAGER_SECRET_ADDR)))?;
    Ok(addr)
}

pub fn get_root_ca_cert() -> Result<String, AppError> {
    let ca_cert = env::var(ROOT_CA_CERT_PATH).map_err(|_| AppError::EnvConfigError(String::from(ROOT_CA_CERT_PATH)))?;
    Ok(ca_cert)
}