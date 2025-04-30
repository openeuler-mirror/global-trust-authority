use std::{io};
use std::collections::HashMap;
use std::ffi::OsString;
use std::process::{Output};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, Value};
use crate::config::config::{OPENBAO_ADDR_ENV_KEY, OPENBAO_TOKEN_ENV_KEY};
use crate::key_manager::base_key_manager::{CommandExecutor};
use crate::utils::env_setting_center::Environment;

pub struct OpenBaoManager {
    command: String,
    args: Vec<String>,
    envs: HashMap<OsString, OsString>
}

impl OpenBaoManager {
    pub fn default () -> OpenBaoManager {
        Self {
            command: String::from("bao"),
            args: Vec::<String>::new(),
            envs: HashMap::from([
                (OsString::from(OPENBAO_TOKEN_ENV_KEY), OsString::from(&Environment::global().root_token)),
                (OsString::from(OPENBAO_ADDR_ENV_KEY), OsString::from(&Environment::global().addr)),
            ])
        }
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

    pub fn version(&mut self, version: &i32) -> &mut Self {
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

    pub fn check_status(&mut self) -> bool {
        log::info!("start check openbao status");
        self.clean();
        self.status().format_json();
        let result = self.run();
        match result {
            Ok(out) => {
                if !out.status.success() {
                    log::error!("openbao status check error, message: {:?}", String::from_utf8_lossy(&out.stderr));
                    return false;
                }
                let data: Value = from_str(&String::from_utf8(out.stdout).unwrap()).unwrap();
                if data["Initialized"] == "false" {
                    log::error!("openbao not initialized, please check");
                    return false;
                }
                if data["Sealed"] == "false" {
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

}

impl CommandExecutor for OpenBaoManager {
    fn run(&self) -> io::Result<Output> {
        self.execute(&self.command, &self.args, &self.envs)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Version {
    pub created_time : String,
    pub deletion_time : String,
    pub destroyed : bool
}

