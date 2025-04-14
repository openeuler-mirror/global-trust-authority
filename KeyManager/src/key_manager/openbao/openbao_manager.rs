use std::collections::HashMap;
use serde_json::{from_str, from_value, Value};
use crate::config::{config};
use crate::key_manager::base_key_manager::{CommandExecutor, PrivateKey};
use crate::key_manager::openbao::openbao_command::{OpenBaoManager, Version};
use crate::key_manager::secret_manager_factory::SecretManager;
use crate::models::cipher_models::CreateCipherReq;
use crate::utils::response::AppError;

impl SecretManager for OpenBaoManager {
    fn get_all_secret(&self) -> Result<HashMap<String, Vec<PrivateKey>>, AppError> {
        let mut bao = OpenBaoManager::default();
        if !bao.check_status() {
            return Err(AppError::OpenbaoNotAvailable(String::new()));
        }
        let mut map = HashMap::new();
        for key in config::TOKEN_ARRAY {
            let result = get_single_private_key(key);
            match result {
                Ok(data) => {
                    map.insert(key.to_string(), data);
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(map)
    }

    fn import_secret(&self, cipher: &CreateCipherReq) -> Result<String, AppError> {
        let mut bao = OpenBaoManager::default();
        if !bao.check_status() {
            return Err(AppError::OpenbaoNotAvailable("service not ready".to_string()));
        }

        let private_key_value;
        if !cipher.private_key.trim().is_empty() {
            private_key_value = cipher.private_key.clone();
        } else {
            private_key_value = format!("@{:?}", cipher.file_path);
        }

        let result = bao.kv().put().mount(&config::SECRET_PATH)
            .map_name(cipher.key_name.as_str())
            .key_value("encoding", cipher.encoding.as_str())
            .key_value("algorithm", cipher.algorithm.as_str())
            .key_value("private_key", private_key_value.as_str()).run();
        match result {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(AppError::OpenbaoCommandExecuteError(stderr.to_string()));
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
}

fn get_single_private_key(key_name: &str) -> Result<Vec<PrivateKey>, AppError> {
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
            json = from_str(&String::from_utf8(out.stdout).unwrap_or("".to_string())).unwrap();
        }
        Err(_e) => {
            log::error!("command execute error, message: {}", _e);
            return Err(AppError::CommandException(String::new()));
        }
    }
    if !json.is_object() || json.get("data").is_none() {
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
    version_vec.sort_by(|item1, item2| item2.cmp(item1));
    for item in version_vec {
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
                vec.push(key);
            }
            Err(_e) => {
                log::error!("command execute error, message: {}", _e);
                return Err(AppError::CommandException(String::new()));
            }
        }
    }
    Ok(vec)
}