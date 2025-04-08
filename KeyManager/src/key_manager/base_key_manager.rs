use std::io;
use std::process::{Command, Output};
use serde::{Deserialize, Serialize};

pub trait CommandExecutor {
    
    fn execute(&self, command: &str, args: &Vec<String>) -> io::Result<Output> {
        log::info!("Executing {:?}", command);
        let output = Command::new(command).args(args).output();
        match output {
            Ok(output) => {
                log::info!("Output {:?}", String::from_utf8_lossy(&output.stdout));
                Ok(output)
            },
            Err(error) => {Err(error)}
        }
    }
    
    fn run(&self) -> io::Result<Output>;

}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize)]
pub struct PrivateKeyVec {
    pub fsk: Vec<PrivateKey>,
    pub nsk: Vec<PrivateKey>,
    pub tsk: Vec<PrivateKey>
}

impl PrivateKeyVec {
    pub fn default() -> PrivateKeyVec {
        Self {
            fsk: Vec::new(),
            nsk: Vec::new(),
            tsk: Vec::new()
        }
    }

    pub fn new(fsk: Vec<PrivateKey>, nsk: Vec<PrivateKey>, tsk: Vec<PrivateKey>) -> Self {
        Self { fsk, nsk, tsk }
    }
}