use std::collections::HashMap;
use std::ffi::{OsString};
use std::io;
use std::process::{Command, Output};
use mockall::automock;
use serde::{Deserialize, Serialize};

#[automock]
pub trait CommandExecutor: Send + Sync {

    fn execute(&self, command: &str, args: &Vec<String>, envs: &HashMap<OsString, OsString>) -> io::Result<Output> {
        log::debug!("start execute command");
        let output = Command::new(command).envs(envs).args(args).output();
        log::debug!("execute command end");
        output
    }

    fn run(&self, command: &str, args: &Vec<String>, envs: &HashMap<OsString, OsString>) -> io::Result<Output>;

}
#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKey {
    #[serde(default)]
    pub version: String,
    pub private_key: String,
    pub algorithm: String,
    pub encoding: String
}

impl PrivateKey {
    pub fn default() -> PrivateKey {
        Self {
            version: String::new(),
            private_key: String::new(),
            algorithm: String::new(),
            encoding: String::new()
        }
    }

    pub fn new(version: String, private_key: String, algorithm: String, encoding: String) -> Self {
        Self { version, private_key, algorithm, encoding }
    }
}