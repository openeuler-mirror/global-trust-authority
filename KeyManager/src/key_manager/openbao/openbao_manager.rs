use serde_json::{from_str, from_value, Value};
use crate::config::{config, status_code};
use crate::key_manager::base_key_manager::{CommandExecutor, PrivateKey, PrivateKeyVec};
use crate::key_manager::openbao::openbao_command::OpenBaoManager;
use crate::key_manager::openbao::openbao_service::Version;
use crate::key_manager::secret_manager_factory::SecretManager;
use crate::models::cipher_models::CreateCipherReq;
use crate::utils::response::AppError;

impl SecretManager for OpenBaoManager {
    fn get_all_secret(&self) -> Result<PrivateKeyVec, i16> {
        let mut bao = OpenBaoManager::default();
        let mut vector = PrivateKeyVec::default();
        if !bao.check_status() {
            return Err(status_code::OPENBAO_NOT_AVAILABLE);
        }
        let fsk = get_single_private_key(config::FSK);
        match fsk {
            Ok(fsk) => {
                vector.fsk = fsk;
            }
            Err(e) => {
                return Err(e);
            }
        }
        let nsk = get_single_private_key(config::NSK);
        match nsk {
            Ok(nsk) => {
                vector.nsk = nsk;
            }
            Err(e) => {
                return Err(e);
            }
        }
        let tsk = get_single_private_key(config::TSK);
        match tsk {
            Ok(tsk) => {
                vector.tsk = tsk;
            }
            Err(e) => {
                return Err(e);
            }
        }
        Ok(vector)
    }

    fn import_secret(&self, cipher: &CreateCipherReq) -> Result<String, AppError> {

        let mut bao = OpenBaoManager::default();
        if !bao.check_status() {
            return Err(AppError::OpenbaoNotAvailable("service not ready".to_string()));
        }

        cipher.validate()?;

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
                Ok(String::from_utf8_lossy(&output.stdout).into())
            },
            Err(_e) => {
                Err(AppError::OpenbaoCommandException("command error".to_string()))
            },
        }
    }
}

fn get_single_private_key(map_name: &str) -> Result<Vec<PrivateKey>, i16> {
    let mut openbao = OpenBaoManager::default();
    let mut vec = Vec::<PrivateKey>::new();
    let result = openbao.kv().metadata().get().format_json().mount(&config::SECRET_PATH).map_name(map_name).run();
    let json: Value;
    match result {
        Ok(out) => {
            if !out.status.success() {
                // 当前数据为空时，此时返回异常
                return Ok(vec);
            }
            json = from_str(&String::from_utf8(out.stdout).unwrap_or("".to_string())).unwrap();
        }
        Err(_e) => {
            return Err(status_code::OPENBAO_COMMAND_EXCEPTION);
        }
    }
    if !json.is_object() || json.get("data").is_none() {
        // todo 异常
        return Err(status_code::OPENBAO_JSON_ERROR);
    }
    if !json["data"].is_object() || json["data"].get("versions").is_none() || !json["data"]["versions"].is_object() {
        // todo 异常
        return Err(status_code::OPENBAO_JSON_ERROR);
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
        let info = openbao.clean().kv().get().format_json().version(&item).mount(&config::SECRET_PATH).map_name(map_name).run();
        match info {
            Ok(info) => {
                if !info.status.success() {
                    log::error!("{}", item);
                    return Err(status_code::OPENBAO_COMMAND_EXECUTE_ERROR);
                }
                let mut detail_info: Value = from_str(&String::from_utf8(info.stdout).unwrap()).unwrap();
                if !detail_info.is_object() || detail_info.get("data").is_none() {
                    log::error!("{}", item);
                    return Err(status_code::OPENBAO_JSON_ERROR);
                }
                if !detail_info["data"].is_object() || detail_info["data"].get("data").is_none() {
                    log::error!("{}", item);
                    return Err(status_code::OPENBAO_JSON_ERROR);
                }
                let detail_data = detail_info["data"]["data"].take();
                let mut key = match from_value::<PrivateKey>(detail_data) {
                    Ok(key) => key,
                    Err(_e) => {
                        log::error!("{}", item);
                        return Err(status_code::OPENBAO_JSON_ERROR)
                    }
                };
                key.version = item.to_string();
                vec.push(key);
            }
            Err(_e) => {
                log::error!("{}", item);
                return Err(status_code::OPENBAO_COMMAND_EXCEPTION);
            }
        }
    }
    Ok(vec)
}