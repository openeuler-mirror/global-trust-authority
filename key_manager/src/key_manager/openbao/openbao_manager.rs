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

use std::string::String;
use std::collections::HashMap;
use async_trait::async_trait;
use serde_json::{from_str, from_value, Value};
use crate::config::config;
use crate::config::config::TOKEN_ARRAY;
use crate::key_manager::base_key_manager::{get_command_service, PrivateKey};
use crate::key_manager::openbao::openbao_command::{OpenBaoManager, Version};
use crate::key_manager::secret_manager_factory::SecretManager;
use crate::models::cipher_models::PutCipherReq;
use crate::utils::errors::AppError;

#[async_trait]
impl SecretManager for OpenBaoManager {
    async fn get_all_secret(&mut self) -> Result<HashMap<String, Vec<PrivateKey>>, AppError> {
        if !self.check_status() {
            return Err(AppError::OpenbaoNotAvailable(String::new()));
        }
        let mut map = HashMap::new();
        for key in TOKEN_ARRAY {
            map.insert(key.to_string(), get_single_private_key(key).await?);
        }
        Ok(map)
    }

    fn import_secret(&mut self, cipher: &PutCipherReq) -> Result<String, AppError> {
        if !self.check_status() {
            return Err(AppError::OpenbaoNotAvailable("service not ready".to_string()));
        }

        let private_key_value;
        if !cipher.private_key.trim().is_empty() {
            private_key_value = cipher.private_key.clone();
        } else {
            private_key_value = format!("@{}", cipher.key_file);
        }

        self.clean().kv().put().mount(&config::SECRET_PATH)
            .map_name(cipher.key_name.as_str())
            .key_value("encoding", cipher.encoding.as_str())
            .key_value("algorithm", cipher.algorithm.as_str())
            .key_value("private_key", private_key_value.as_str());
        let result = get_command_service().execute(self.get_command(), self.get_args(), self.get_envs());
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

    fn init_system(&mut self) -> Result<(), AppError> {
        // 设置当前openbao的登录环境
        let check = self.check_secrets()?;
        if !check {
            self.create_secrets()?;
        }
        for item in TOKEN_ARRAY {
            if self.check_metadata_map(item)? {
                continue
            }
            self.create_metadata(item)?;
        }
        Ok(())
    }
}

impl OpenBaoManager {
    /// desc: create single secrets in openbao, only contain a map
    fn create_secrets(&mut self) -> Result<(), AppError> {
        self.clean().secrets().enable().path(config::SECRET_PATH).kv_v2();
        let result = get_command_service().execute(self.get_command(), self.get_args(), self.get_envs());
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

    /// desc: check current secrets has been created, select all secrets to check
    /// # Errors:
    ///     result is not match fixed format
    pub fn check_secrets(&mut self) -> Result<bool, AppError> {
        // 创建密钥路径
        self.clean().secrets().list().detailed().format_json();
        let result = get_command_service().execute(self.get_command(), self.get_args(), self.get_envs());
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
                Ok(json.as_object().map_or(false, | itme| itme.contains_key(format!("{}/", config::SECRET_PATH).as_str())))
            },
            Err(err) => {
                log::error!("failed to enable secrets, err: {}", err);
                Err(AppError::CommandException(String::new()))
            }
        }
    }

    fn check_metadata_map(&mut self, item: &str) -> Result<bool, AppError> {
        self.clean().kv().metadata().get().mount(config::SECRET_PATH).map_name(item);
        let result = get_command_service().execute(self.get_command(), self.get_args(), self.get_envs());
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

    /// desc: create single metadata, this metadata is openbao v2 path
    /// param: 
    ///     item: metadata name 
    /// # Errors:
    ///     shell command execute error
    pub fn create_metadata(&mut self, item: &str) -> Result<(), AppError> {
        self.clean().kv().metadata().put().mount(config::SECRET_PATH).max_versions(&u32::MAX).map_name(item);
        let result = get_command_service().execute(self.get_command(), self.get_args(), self.get_envs());
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
    openbao.clean().kv().metadata().get().format_json().mount(&config::SECRET_PATH).map_name(key_name);
    let result = get_command_service().execute(openbao.get_command(), openbao.get_args(), openbao.get_envs());
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
    let versions = if let Some(obj) = json["data"]["versions"].as_object() {
        obj
    } else { 
        return Err(AppError::OpenbaoJsonError(String::new())); 
    };
    let mut version_vec = Vec::<u32>::new();
    for (key, value) in versions {
        let info: Version = from_value(value.clone()).unwrap_or(Version::default());
        if info.deletion_time.is_empty() && !info.destroyed {
            version_vec.push(key.parse::<u32>().unwrap_or_else(|_| 0));
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

async fn get_version_data(key_name: &str, item: &u32) -> Result<PrivateKey, AppError> {
    let mut openbao =  OpenBaoManager::default();
    let private_key;
    openbao.clean().kv().get().format_json().version(&item).mount(&config::SECRET_PATH).map_name(key_name);
    let info = get_command_service().execute(openbao.get_command(), openbao.get_args(), openbao.get_envs());
    match info {
        Ok(info) => {
            if !info.status.success() {
                log::error!("{} private key version[{}] select error", key_name, item);
                return Err(AppError::OpenbaoCommandExecuteError(String::new()));
            }
            let mut detail_info: Value = from_str(&String::from_utf8(info.stdout).unwrap_or("{}".to_string())).unwrap_or(Value::Null);
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


#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::{ExitStatus, Output};
    use std::sync::Arc;
    use mockall::predicate::{always, eq};
    use serde_json::json;
    use serial_test::serial;
    use crate::config::config::{self, TOKEN_ARRAY};
    use crate::key_manager::base_key_manager::{MockCommandExecutor, MOCK_COMMAND_EXECUTOR};
    use crate::key_manager::openbao::openbao_command::OpenBaoManager;
    use crate::key_manager::secret_manager_factory::{SecretManager, SecretManagerFactory, SecretManagerType};
    use crate::models::cipher_models::PutCipherReq;

    fn mock_check_status_success(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        let vec: Vec<String> = bao.clean().status().format_json().get_args().to_vec();
        mock.expect_execute()
            .with(always(), eq(vec), always())
            .returning(move |_, _, _| {
                Ok(Output { 
                    status: ExitStatus::default(), 
                    stdout: serde_json::to_vec(&json!({
                        "type": "shamir",
                        "initialized": true,
                        "sealed": false,
                        "t": 3,
                        "n": 5,
                        "progress": 0,
                        "nonce": "",
                        "version": "2.2.0",
                        "build_date": "2025-03-05T13:07:08Z",
                        "migration": false,
                        "cluster_name": "vault-cluster-29ba4222",
                        "cluster_id": "9bf3fb42-9eeb-b89e-2965-2064741d3aac",
                        "recovery_seal": false,
                        "storage_type": "file",
                        "ha_enabled": false,
                        "active_time": "0001-01-01T00:00:00Z"
                    })).unwrap(),
                    stderr: Vec::new() 
                })
            });
    }

    fn mock_get_metadata_success(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        for ele in TOKEN_ARRAY {
            let vec: Vec<String> = bao.clean().kv().metadata().get().format_json().mount(&config::SECRET_PATH).map_name(ele).get_args().to_vec();
            mock.expect_execute()
                .with(always(), eq(vec), always())
                .returning(move |_, _, _| {
                    Ok(Output { 
                        status: ExitStatus::default(), 
                        stdout: serde_json::to_vec(&json!({
                            "request_id": "b83d6ae9-bd83-275d-2e6e-7dfd569b60e8",
                            "lease_id": "",
                            "lease_duration": 0,
                            "renewable": false,
                            "data": {
                                "cas_required": false,
                                "created_time": "2025-05-12T02:38:08.436254138Z",
                                "current_version": 63,
                                "custom_metadata": null,
                                "delete_version_after": "0s",
                                "max_versions": 0,
                                "oldest_version": 54,
                                "updated_time": "2025-05-15T07:53:16.257468396Z",
                                "versions": {
                                    "1": {
                                        "created_time": "2025-05-15T07:52:58.171754685Z",
                                        "deletion_time": "",
                                        "destroyed": false
                                    }
                                }
                            },
                            "warnings": null
                        })).unwrap(),
                        stderr: Vec::new() 
                    })
                });
        }
        
    }

    fn mock_get_single_success(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        for ele in TOKEN_ARRAY {
            let vec: Vec<String> = bao.clean().kv().get().format_json().version(&1).mount(&config::SECRET_PATH).map_name(ele).get_args().to_vec();
            mock.expect_execute()
                .with(always(), eq(vec), always())
                .returning(move |_, _, _| {
                    Ok(Output { 
                        status: ExitStatus::default(), 
                        stdout: serde_json::to_vec(&json!({
                            "request_id": "4fbdfdaf-05ec-dc23-43cb-da3ac3acbc76",
                            "lease_id": "",
                            "lease_duration": 0,
                            "renewable": false,
                            "data": {
                                "data": {
                                "algorithm": "rsa_3072",
                                "encoding": "pem",
                                "private_key": "Hello World"
                                },
                                "metadata": {
                                "created_time": "2025-05-15T07:53:16.257468396Z",
                                "custom_metadata": null,
                                "deletion_time": "",
                                "destroyed": false,
                                "version": 1
                                }
                            },
                            "warnings": null
                        })).unwrap(),
                        stderr: Vec::new() 
                    })
                });
        }
    }

    fn mock_check_secret_success(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        let vec: Vec<String> = bao.clean().secrets().list().detailed().format_json().get_args().to_vec();
        mock.expect_execute()
            .with(always(), eq(vec), always())
            .returning(move |_, _, _| {
                Ok(Output { 
                    status: ExitStatus::default(), 
                    stdout: serde_json::to_vec(&json!({})).unwrap(),
                    stderr: Vec::new() 
                })
            });
    }

    fn mock_create_secret_success(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        let vec: Vec<String> = bao.clean().secrets().enable().path(config::SECRET_PATH).kv_v2().get_args().to_vec();
        mock.expect_execute()
            .with(always(), eq(vec), always())
            .returning(move |_, _, _| {
                Ok(Output { 
                    status: ExitStatus::default(), 
                    stdout: serde_json::to_vec(&json!({})).unwrap(),
                    stderr: Vec::new() 
                })
            });
    }

    fn mock_check_metadata_map_success(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        for ele in TOKEN_ARRAY {
            let vec: Vec<String> = bao.clean().kv().metadata().get().mount(config::SECRET_PATH).map_name(ele).get_args().to_vec();
            mock.expect_execute()
                .with(always(), eq(vec), always())
                .returning(move |_, _, _| {
                    Ok(Output { 
                        status: ExitStatus::default(), 
                        stdout: serde_json::to_vec(&json!({})).unwrap(),
                        stderr: Vec::new() 
                    })
                });
        }
    }

    fn mock_check_metadata_map_fail(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        for ele in TOKEN_ARRAY {
            let vec: Vec<String> = bao.clean().kv().metadata().get().mount(config::SECRET_PATH).map_name(ele).get_args().to_vec();
            mock.expect_execute()
                .with(always(), eq(vec), always())
                .returning(move |_, _, _| {
                    Ok(Output { 
                        status: ExitStatus::from_raw(1), 
                        stdout: serde_json::to_vec(&json!({})).unwrap(),
                        stderr: Vec::new() 
                    })
                });
        }
    }

    fn mock_create_metadata_success(mock: &mut MockCommandExecutor) {
        let mut bao = OpenBaoManager::new();
        for ele in TOKEN_ARRAY {
            let vec: Vec<String> = bao.clean().kv().metadata().put().mount(config::SECRET_PATH).max_versions(&u32::MAX).map_name(ele).get_args().to_vec();
            mock.expect_execute()
                .with(always(), eq(vec), always())
                .returning(move |_, _, _| {
                    Ok(Output { 
                        status: ExitStatus::default(), 
                        stdout: serde_json::to_vec(&json!({})).unwrap(),
                        stderr: Vec::new() 
                    })
                });
        }
    }

    fn mock_import_secrets_success(mock: &mut MockCommandExecutor, cipher: &PutCipherReq) {
        let mut bao = OpenBaoManager::new();
        let vec: Vec<String> = bao.clean().clean().kv().put().mount(&config::SECRET_PATH)
            .map_name(cipher.key_name.as_str())
            .key_value("encoding", cipher.encoding.as_str())
            .key_value("algorithm", cipher.algorithm.as_str())
            .key_value("private_key", cipher.private_key.as_str()).get_args().to_vec();
        mock.expect_execute()
            .with(always(), eq(vec), always())
            .returning(move |_, _, _| {
                Ok(Output { 
                    status: ExitStatus::default(), 
                    stdout: serde_json::to_vec(&json!({})).unwrap(),
                    stderr: Vec::new() 
                })
            });
    }

    #[tokio::test]
    #[serial] 
    async fn test_get_all_secrate_success() {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
        let config_path = test_dir.join(".env");
        let _ = dotenv::from_path(config_path);

        let mut mock = MockCommandExecutor::new();
        mock_check_status_success(&mut mock);
        mock_get_metadata_success(&mut mock);
        mock_get_single_success(&mut mock);
        
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = Some(Arc::new(mock));

        let mut bao = SecretManagerFactory::create_manager(SecretManagerType::OpenBao);
        let result = bao.get_all_secret().await;
        assert!(result.is_ok());
        let map = result.unwrap();
        for ele in TOKEN_ARRAY {
            assert!(map.contains_key(ele));
            assert!(!map.get(ele).unwrap().is_empty())
        }
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = None;
    }

    #[test]
    #[serial] 
    fn test_init_system_success() {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
        let config_path = test_dir.join(".env");
        let _ = dotenv::from_path(config_path);

        let mut mock = MockCommandExecutor::new();
        mock_check_secret_success(&mut mock);
        mock_create_secret_success(&mut mock);
        mock_check_metadata_map_fail(&mut mock);
        mock_create_metadata_success(&mut mock);
        
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = Some(Arc::new(mock));

        let mut bao = OpenBaoManager::new();
        let result = bao.init_system();
        assert!(result.is_ok());
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = None;
    }

    #[test]
    #[serial] 
    fn test_init_system_not_create_metadata() {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
        let config_path = test_dir.join(".env");
        let _ = dotenv::from_path(config_path);

        let mut mock = MockCommandExecutor::new();
        mock_check_secret_success(&mut mock);
        mock_create_secret_success(&mut mock);
        mock_check_metadata_map_success(&mut mock);
        
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = Some(Arc::new(mock));

        let mut bao = OpenBaoManager::new();
        let result = bao.init_system();
        assert!(result.is_ok());
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = None;
    }

    #[test]
    #[serial] 
    fn test_import_sercts_metadata() {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
        let config_path = test_dir.join(".env");
        let _ = dotenv::from_path(config_path);
        let cipher = PutCipherReq {
            key_name: String::from("NSK"),
            encoding: String::from("pem"),
            algorithm: String::from("rsa_3072"),
            private_key: String::from("hello world"),
            key_file: String:: from("hello world")
        };
        let mut mock = MockCommandExecutor::new();
        mock_check_status_success(&mut mock);
        mock_import_secrets_success(&mut mock, &cipher);
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = Some(Arc::new(mock));
        let mut bao = OpenBaoManager::new();
        let result = bao.import_secret(&cipher);
        assert!(result.is_ok());
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = None;
    }
}