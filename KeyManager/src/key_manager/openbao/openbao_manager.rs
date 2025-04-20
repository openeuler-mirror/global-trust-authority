use std::string::String;
use std::collections::HashMap;
use std::env;
use async_trait::async_trait;
use serde_json::{from_str, from_value, Value};
use crate::config::{config};
use crate::config::config::TOKEN_ARRAY;
use crate::key_manager::base_key_manager::{CommandExecutor, PrivateKey};
use crate::key_manager::openbao::openbao_command::{OpenBaoManager, Version};
use crate::key_manager::secret_manager_factory::SecretManager;
use crate::models::cipher_models::PutCipherReq;
use crate::utils::env_setting_center::Environment;
use crate::utils::errors::AppError;

#[async_trait]
impl SecretManager for OpenBaoManager {
    async fn get_all_secret(&self) -> Result<HashMap<String, Vec<PrivateKey>>, AppError> {
        let mut bao = OpenBaoManager::default();
        if !bao.check_status() {
            return Err(AppError::OpenbaoNotAvailable(String::new()));
        }
        let mut map = HashMap::new();
        for key in TOKEN_ARRAY {
            map.insert(key.to_string(), get_single_private_key(key).await?);
        }
        Ok(map)
    }

    fn import_secret(&self, cipher: &PutCipherReq) -> Result<String, AppError> {
        let mut bao = OpenBaoManager::default();
        if !bao.check_status() {
            return Err(AppError::OpenbaoNotAvailable("service not ready".to_string()));
        }

        let private_key_value;
        if !cipher.private_key.trim().is_empty() {
            private_key_value = cipher.private_key.clone();
        } else {
            private_key_value = format!("@{}", cipher.key_file);
        }

        let result = bao.clean().kv().put().mount(&config::SECRET_PATH)
            .map_name(cipher.key_name.as_str())
            .key_value("encoding", cipher.encoding.as_str())
            .key_value("algorithm", cipher.algorithm.as_str())
            .key_value("private_key", private_key_value.as_str()).run();
        match result {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(AppError::CommandException(stderr.to_string()));
                }
                log::info!("import secret successfully");
                Ok(String::from_utf8_lossy(&output.stdout).into())
            },
            Err(_e) => {
                log::error!("failed to import_secret, command execute error, err: {}", _e);
                Err(AppError::CommandException("command error".to_string()))
            },
        }
    }

    fn init_system(&self) -> Result<(), AppError> {
        // 设置当前openbao的登录环境
        unsafe {
            env::set_var("BAO_TOKEN", &Environment::global().root_token);
        }
        let mut bao = OpenBaoManager::default();
        let check = Self::check_secrets(&mut bao)?;
        if !check {
            Self::create_secrets(&mut bao)?;
        }
        for item in TOKEN_ARRAY {
            if Self::check_metadata_map(&mut bao, item)? {
                continue
            }
            Self::create_metadata(&mut bao, item)?;
        }
        Ok(())
    }
}

impl OpenBaoManager {
    fn create_secrets(bao: &mut OpenBaoManager) -> Result<(), AppError> {
        bao.clean();
        let result = bao.secrets().enable().path(config::SECRET_PATH).kv_v2().run();
        match result {
            Ok(output) => {
                if !output.status.success() {
                    log::error!("failed to enable secrets, err: {}", String::from_utf8_lossy(&output.stderr));
                    return Err(AppError::OpenbaoCommandExecuteError(String::new()));
                }
            },
            Err(err) => {
                log::error!("failed to enable secrets, err: {}", err);
                return Err(AppError::CommandException(String::new()));
            }
        }
        Ok(())
    }

    fn check_secrets(bao: &mut OpenBaoManager) -> Result<bool, AppError> {
        bao.clean();
        // 创建密钥路径
        let result = bao.secrets().list().detailed().format_json().run();
        match result {
            Ok(output) => {
                if !output.status.success() {
                    log::error!("select secrets error, err: {}", String::from_utf8_lossy(&output.stderr));
                    return Err(AppError::OpenbaoCommandExecuteError(String::new()));
                }
                let json:Value = from_str(&String::from_utf8(output.stdout).unwrap_or("{}".to_string())).unwrap_or(Value::Null);
                if json.is_null() || !json.is_object() {
                    log::error!("select secrets error, err: {}", String::from_utf8_lossy(&output.stderr));
                    return Err(AppError::OpenbaoCommandExecuteError(String::new()));
                }
                Ok(json.as_object().unwrap().contains_key(format!("{}/", config::SECRET_PATH).as_str()))
            },
            Err(err) => {
                log::error!("failed to enable secrets, err: {}", err);
                Err(AppError::CommandException(String::new()))
            }
        }
    }

    fn check_metadata_map(bao: &mut OpenBaoManager, item: &str) -> Result<bool, AppError> {
        bao.clean();
        let result = bao.kv().metadata().get().mount(config::SECRET_PATH).map_name(item).run();
        match result {
            Ok(output) => {
                Ok(output.status.success())
            },
            Err(err) => {
                log::error!("failed to enable secrets map, err: {}", err);
                Err(AppError::CommandException(String::new()))
            }
        }
    }

    fn create_metadata(bao: &mut OpenBaoManager, item: &str) -> Result<(), AppError> {
        bao.clean();
        let result = bao.kv().metadata().put().mount(config::SECRET_PATH).max_versions(&u32::MAX).map_name(item).run();
        match result {
            Ok(output) => {
                if !output.status.success() {
                    log::error!("failed to create secrets map, err: {}", String::from_utf8_lossy(&output.stderr));
                    return Err(AppError::OpenbaoCommandExecuteError(String::new()));
                }
                Ok(())
            },
            Err(err) => {
                log::error!("failed to create secrets map, err: {}", err);
                Err(AppError::CommandException(String::new()))
            }
        }
    }
}

async fn get_single_private_key(key_name: &str) -> Result<Vec<PrivateKey>, AppError> {
    log::info!("start get {} private key", key_name);
    let mut openbao = OpenBaoManager::default();
    let mut vec = Vec::<PrivateKey>::new();
    let result = openbao.kv().metadata().get().format_json().mount(&config::SECRET_PATH).map_name(key_name).run();
    let json: Value;
    match result {
        Ok(out) => {
            if !out.status.success() {
                log::warn!("private key not found, message: {}", String::from_utf8_lossy(&out.stderr));
                return Ok(vec);
            }
            json = from_str(&String::from_utf8(out.stdout).unwrap_or("{}".to_string())).unwrap_or(Value::Null);
        }
        Err(_e) => {
            log::error!("command execute error, message: {}", _e);
            return Err(AppError::CommandException(String::new()));
        }
    }
    if json.is_null() || !json.is_object() || json.get("data").is_none() {
        log::error!("json or json[data] is error");
        return Err(AppError::OpenbaoJsonError(String::new()));
    }
    if !json["data"].is_object() || json["data"].get("versions").is_none() || !json["data"]["versions"].is_object() {
        log::error!("json[data] or json[data][versions] is error");
        return Err(AppError::OpenbaoJsonError(String::new()));
    }
    let versions = json["data"]["versions"].as_object().unwrap();
    let mut version_vec = Vec::<i32>::new();
    for (key, value) in versions {
        let info: Version = from_value(value.clone()).unwrap();
        if info.deletion_time.is_empty() && !info.destroyed {
            version_vec.push(key.parse::<i32>().unwrap());
        }
    }
    let mut tasks = Vec::new();
    for item in version_vec {
        let key_name = key_name.to_string();
        tasks.push(tokio::task::spawn(async move {
            get_version_data(&key_name.to_string(), &item).await
        }));
    }
    let results: Vec<Result<PrivateKey, AppError>> = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|res| res.unwrap_or_else(|join_error| {  // 处理 tokio::task::JoinError
            log::error!("Task failed: {}", join_error);
            Err(AppError::AsyncExecuteError(String::new()))
        }))
        .collect();
    for item in results {
        vec.push(item?);
    }
    vec.sort_by(|i1, i2| i2.version[1..].parse::<u32>().ok().cmp(&i1.version[1..].parse::<u32>().ok()));
    Ok(vec)
}

async fn get_version_data(key_name: &str, item: &i32) -> Result<PrivateKey, AppError> {
    let mut openbao =  OpenBaoManager::default();
    let mut private_key = PrivateKey::default();
    let info = openbao.clean().kv().get().format_json().version(&item).mount(&config::SECRET_PATH).map_name(key_name).run();
    match info {
        Ok(info) => {
            if !info.status.success() {
                log::error!("{} private key version[{}] select error", key_name, item);
                return Err(AppError::OpenbaoCommandExecuteError(String::new()));
            }
            let mut detail_info: Value = from_str(&String::from_utf8(info.stdout).unwrap()).unwrap();
            if !detail_info.is_object() || detail_info.get("data").is_none() {
                log::error!("json or json[data] is error");
                return Err(AppError::OpenbaoJsonError(String::new()));
            }
            if !detail_info["data"].is_object() || detail_info["data"].get("data").is_none() {
                log::error!("json[data] or json[data][data] is error");
                return Err(AppError::OpenbaoJsonError(String::new()));
            }
            let detail_data = detail_info["data"]["data"].take();
            let mut key = match from_value::<PrivateKey>(detail_data) {
                Ok(key) => key,
                Err(_e) => {
                    log::error!("openbao data is not match private key, key: {}, version: {}", key_name, item);
                    return Err(AppError::OpenbaoJsonError(String::new()))
                }
            };
            key.version = format!("v{}", item.to_string());
            private_key = key.clone();
        }
        Err(_e) => {
            log::error!("command execute error, message: {}", _e);
            return Err(AppError::CommandException(String::new()));
        }
    }
    Ok(private_key)
}