use std::io;
use std::process::{Command, Output};
use serde::{Deserialize, Deserializer, Serialize};

pub trait CommandExecutor {

    fn execute(&self, command: &str, args: &Vec<String>) -> io::Result<Output> {
        log::debug!("start execute command");
        let output = Command::new(command).args(args).output();
        log::debug!("execute command end");
        output
    }

    fn run(&self) -> io::Result<Output>;

}

fn remove_newlines<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(s.replace("\n", ""))
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey {
    #[serde(default)]
    pub version: String,
    #[serde(deserialize_with = "remove_newlines")]
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