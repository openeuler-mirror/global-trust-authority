use std::{io};
use std::process::{Output};
use serde_json::{from_str, Value};
use crate::key_manager::base_key_manager::{CommandExecutor};

pub struct Openbao {
    command: String,
    args: Vec<String>
}

impl Openbao {
    pub fn default () -> Openbao {
        Self {
            command: String::from("bao"),
            args: Vec::<String>::new(),
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
        self.args.push(format!("path={}", path));
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

    pub fn clean(&mut self) -> &mut Self {
        self.args.clear();
        self
    }

    pub fn check_status(&mut self) -> bool {
        self.clean();
        self.status().format_json();
        let result = self.run();
        match result {
            Ok(out) => {
                if !out.status.success() { 
                    return false;
                }
                let data: Value = from_str(&String::from_utf8(out.stdout).unwrap()).unwrap();
                if data["Initialized"] == "false" { 
                    // 未初始化 todo
                }
                if data["Sealed"] == "false" { 
                    // openbao处于lock todo
                }
                
                return true
            }
            Err(_e) => {
                // 当前命令执行异常
                return false
            }
        }
    }

}

impl CommandExecutor for Openbao {
    fn run(&self) -> io::Result<Output> {
        self.execute(&self.command, &self.args)
    }
}