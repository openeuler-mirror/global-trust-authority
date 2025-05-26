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

use mockall::automock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::process::{Command, Output};
use std::sync::*;

#[automock]
pub trait CommandExecutor {
    fn execute(&self, command: &str, args: &Vec<String>, envs: &HashMap<OsString, OsString>) -> io::Result<Output>;
}
pub struct CommandService;
impl CommandExecutor for CommandService {
    fn execute(&self, command: &str, args: &Vec<String>, envs: &HashMap<OsString, OsString>) -> io::Result<Output> {
        log::debug!("start execute command");
        let output = Command::new(command).envs(envs).args(args).output();
        log::debug!("execute command end");
        output
    }
}

#[cfg(test)]
lazy_static::lazy_static! {
    pub static ref MOCK_COMMAND_EXECUTOR: Mutex<Option<Arc<dyn CommandExecutor + Send + Sync>>> = Mutex::new(None);
}

pub fn get_command_service() -> Arc<dyn CommandExecutor + Send + Sync> {
    #[cfg(test)] {
        MOCK_COMMAND_EXECUTOR.lock().unwrap().as_ref().expect("mock init error").clone()
    }
    #[cfg(not(test))] {
        Arc::new(CommandService)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKey {
    #[serde(default)]
    pub version: String,
    pub private_key: String,
    pub algorithm: String,
    pub encoding: String,
}

impl PrivateKey {
    pub fn default() -> PrivateKey {
        Self { version: String::new(), private_key: String::new(), algorithm: String::new(), encoding: String::new() }
    }

    pub fn new(version: String, private_key: String, algorithm: String, encoding: String) -> Self {
        Self { version, private_key, algorithm, encoding }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::process::{ExitStatus, Output};
    use std::sync::Arc;
    use crate::key_manager::base_key_manager::{get_command_service, MockCommandExecutor, MOCK_COMMAND_EXECUTOR};

    #[test]
    fn test_command_executor_mock() {
        let mut mock = MockCommandExecutor::new();
        // 模拟成功的命令执行
        mock.expect_execute().return_once(move |_, _, _| {
            Ok(Output { status: ExitStatus::default(), stdout: b"success".to_vec(), stderr: Vec::new() })
        });
        *MOCK_COMMAND_EXECUTOR.lock().unwrap() = Some(Arc::new(mock));

        let vec: Vec<String> = vec![String::from("status")];
        let result = get_command_service().execute("bao", &vec, &HashMap::new());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().stdout, b"success");
    }
}