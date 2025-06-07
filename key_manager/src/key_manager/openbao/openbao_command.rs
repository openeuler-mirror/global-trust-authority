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

use crate::config::config::{OPENBAO_ADDR_ENV_KEY, OPENBAO_TOKEN_ENV_KEY};
use crate::key_manager::base_key_manager::get_command_service;
use crate::utils::env_setting_center::Environment;
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_str};
use std::collections::HashMap;
use std::ffi::OsString;

pub struct OpenBaoManager {
    command: String,
    args: Vec<String>,
    envs: HashMap<OsString, OsString>,
}

impl OpenBaoManager {
    pub fn default() -> OpenBaoManager {
        Self {
            command: String::from("bao"),
            args: Vec::<String>::new(),
            envs: HashMap::from([
                (OsString::from(OPENBAO_TOKEN_ENV_KEY), OsString::from(&Environment::global().root_token)),
                (OsString::from(OPENBAO_ADDR_ENV_KEY), OsString::from(&Environment::global().addr)),
            ]),
        }
    }

    pub fn new() -> OpenBaoManager {
        Self { command: String::new(), args: Vec::<String>::new(), envs: HashMap::from([])}
    }

    pub fn status(&mut self) -> &mut Self {
        self.args.push(String::from("status"));
        self
    }

    pub fn format_json(&mut self) -> &mut Self {
        self.args.push(String::from("--format=json"));
        self
    }

    pub fn kv(&mut self) -> &mut Self {
        self.args.push(String::from("kv"));
        self
    }

    pub fn put(&mut self) -> &mut Self {
        self.args.push(String::from("put"));
        self
    }

    pub fn mount(&mut self, path: &str) -> &mut Self {
        self.args.push(format!("--mount={}", path));
        self
    }

    pub fn map_name(&mut self, name: &str) -> &mut Self {
        self.args.push(String::from(name));
        self
    }

    pub fn key_value(&mut self, key: &str, value: &str) ->&mut Self {
        self.args.push(format!("{}={}", key, value));
        self
    }

    pub fn value_file_path(&mut self, path: &str) -> &mut Self {
        self.args.push(format!("@{}", path));
        self
    }

    pub fn secrets(&mut self) -> &mut Self {
        self.args.push(String::from("secrets"));
        self
    }

    pub fn enable(&mut self) -> &mut Self {
        self.args.push(String::from("enable"));
        self
    }

    pub fn path(&mut self, path: &str) -> &mut Self {
        self.args.push(format!("-path={}", path));
        self
    }

    pub fn kv_v2(&mut self) -> &mut Self {
        self.args.push(String::from("kv-v2"));
        self
    }

    pub fn list(&mut self) -> &mut Self {
        self.args.push(String::from("list"));
        self
    }

    pub fn detailed(&mut self) -> &mut Self {
        self.args.push(String::from("--detailed"));
        self
    }

    pub fn metadata(&mut self) -> &mut Self {
        self.args.push(String::from("metadata"));
        self
    }

    pub fn get(&mut self) -> &mut Self {
        self.args.push(String::from("get"));
        self
    }

    pub fn version(&mut self, version: &u32) -> &mut Self {
        self.args.push(format!("--version={}", version));
        self
    }

    pub fn max_versions(&mut self, max_versions: &u32) -> &mut Self {
        self.args.push(format!("--max-versions={}", max_versions));
        self
    }

    pub fn clean(&mut self) -> &mut Self {
        self.args.clear();
        self
    }

    /// desc: check openbao status, check if the status is health
    pub fn check_status(&mut self) -> bool {
        log::info!("start check openbao status");
        self.clean().status().format_json();
        let result = get_command_service().execute(self.get_command(), self.get_args(), self.get_envs());
        match result {
            Ok(out) => {
                if !out.status.success() {
                    log::error!("openbao status check error, message: {:?}", String::from_utf8_lossy(&out.stderr));
                    return false;
                }
                let data: Value = from_str(&String::from_utf8(out.stdout).unwrap_or("{}".to_string())).unwrap_or(Value::Null);
                if data["Initialized"] == false {
                    log::error!("openbao not initialized, please check");
                    return false;
                }
                if data["Sealed"] == true {
                    log::error!("openbao is seal, please unseal openbao");
                    return false;
                }
                log::info!("openbao is healthy");
                true
            }
            Err(_e) => {
                log::error!("command execute error, message: {}", _e);
                false
            }
        }
    }

    pub fn set_command(&mut self, command: String) {
        self.command = command;
    }

    pub fn set_args(&mut self, args: Vec<String>) {
        self.args = args;
    }

    pub fn set_envs(&mut self, envs: HashMap<OsString, OsString>) {
        self.envs = envs;
    }

    pub fn get_command(&self) -> &str {
        &self.command
    }

    pub fn get_args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn get_envs(&self) -> &HashMap<OsString, OsString> {
        &self.envs
    }
}

#[derive(Serialize, Deserialize)]
pub struct Version {
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
}

impl Version {
    pub fn default() -> Self {
        Self{
            created_time: "".to_string(),
            deletion_time: "".to_string(),
            destroyed: false,
        }
    }
}
