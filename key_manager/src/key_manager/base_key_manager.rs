use std::collections::HashMap;
use std::ffi::{OsString};
use std::io;
use std::process::{Command, Output};
use mockall::automock;
use serde::{Deserialize, Serialize};

#[automock]
pub trait CommandExecutor {

    fn execute(&self, command: &str, args: &Vec<String>, envs: &HashMap<OsString, OsString>) -> io::Result<Output> {
        log::debug!("start execute command");
        let output = Command::new(command).envs(envs).args(args).output();
        log::debug!("execute command end");
        output
    }

    fn run(&self) -> io::Result<Output>;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::process::Output;
    use mockall::predicate::*;

    // 为测试创建一个 mock 实现
    struct MockCommandExecutor;

    impl CommandExecutor for MockCommandExecutor {
        fn execute(&self, command: &str, _args: &Vec<String>, _envs: &HashMap<OsString, OsString>) -> io::Result<Output> {
            // 模拟成功执行
            if command == "success" {
                Ok(Output {
                    status: std::process::ExitStatus::default(),
                    stdout: b"success output".to_vec(),
                    stderr: vec![],
                })
            }
            // 模拟失败执行
            else if command == "failure" {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "command failed"))
            } else {
                // 默认模拟
                Ok(Output {
                    status: std::process::ExitStatus::default(),
                    stdout: b"default output".to_vec(),
                    stderr: vec![],
                })
            }
        }

        fn run(&self) -> io::Result<Output> {
            // 简单模拟 run 方法
            Ok(Output {
                status: std::process::ExitStatus::default(),
                stdout: b"run output".to_vec(),
                stderr: vec![],
            })
        }
    }

    #[test]
    fn test_private_key_default() {
        let key = PrivateKey::default();
        assert!(key.version.is_empty());
        assert!(key.private_key.is_empty());
        assert!(key.algorithm.is_empty());
        assert!(key.encoding.is_empty());
    }

    #[test]
    fn test_private_key_new() {
        let key = PrivateKey::new(
            "v1".to_string(),
            "private".to_string(),
            "RSA".to_string(),
            "PEM".to_string()
        );

        assert_eq!(key.version, "v1");
        assert_eq!(key.private_key, "private");
        assert_eq!(key.algorithm, "RSA");
        assert_eq!(key.encoding, "PEM");
    }

    #[test]
    fn test_command_executor_success() {
        let executor = MockCommandExecutor;
        let args = vec!["arg1".to_string()];
        let mut envs = HashMap::new();
        envs.insert(OsString::from("ENV_VAR"), OsString::from("value"));

        let result = executor.execute("success", &args, &envs);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.stdout, b"success output");
    }

    #[test]
    fn test_command_executor_failure() {
        let executor = MockCommandExecutor;
        let args = vec!["arg1".to_string()];
        let envs = HashMap::new();

        let result = executor.execute("failure", &args, &envs);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn test_command_executor_run() {
        let executor = MockCommandExecutor;
        let result = executor.run();
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.stdout, b"run output");
    }
}