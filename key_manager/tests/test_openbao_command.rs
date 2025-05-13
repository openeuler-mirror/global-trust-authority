#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::process::{ExitStatus, Output};
    use std::ffi::OsString;
    use std::io;
    use mockall::predicate::always;
    use serde_json::json;
    use key_managerd::config::config::{OPENBAO_ADDR_ENV_KEY, OPENBAO_TOKEN_ENV_KEY};
    use key_managerd::key_manager::base_key_manager::MockCommandExecutor;
    use key_managerd::key_manager::openbao::openbao_command::OpenBaoManager;

    #[test]
    fn test_openbao_manager_default() {
        let mock = MockCommandExecutor::new();
        let mut manager = OpenBaoManager::new(Box::new(mock));
        manager.set_command(String::from("bao"));
        let vec = Vec::<String>::new();
        manager.set_args(vec);
        let mut map:HashMap<OsString, OsString> = HashMap::new();
        map.insert(OsString::from(OPENBAO_TOKEN_ENV_KEY), OsString::from("token"));
        map.insert(OsString::from(OPENBAO_ADDR_ENV_KEY), OsString::from("addr"));
        manager.set_envs(map);
        assert_eq!(manager.command(), "bao");
        assert!(manager.args().is_empty());
        assert!(manager.envs().contains_key(&OsString::from(OPENBAO_TOKEN_ENV_KEY)));
        assert!(manager.envs().contains_key(&OsString::from(OPENBAO_ADDR_ENV_KEY)));
    }

    #[test]
    fn test_command_building() {
        let mock = MockCommandExecutor::new();
        let mut manager = OpenBaoManager::new(Box::new(mock));
        manager.kv().put().mount("test_path").map_name("test_name");
        assert_eq!(manager.args().contains(&String::from("kv")), true);
        assert_eq!(manager.args().contains(&String::from("put")), true);
        assert_eq!(manager.args().contains(&String::from("--mount=test_path")), true);
        assert_eq!(manager.args().contains(&String::from("test_name")), true);
    }

    #[test]
    fn test_clean() {
        let mock = MockCommandExecutor::new();
        let mut manager = OpenBaoManager::new(Box::new(mock));
        manager.kv().put();
        assert!(!manager.args().is_empty());

        manager.clean();
        assert!(manager.args().is_empty());
    }

    #[test]
    fn test_check_status_success() {
        let healthy_status = json!({
            "Initialized": true,
            "Sealed": false
        }).to_string();

        let mut mock = MockCommandExecutor::new();
        mock.expect_execute().with(always(), always(), always()).return_once(move |_, _, _|Ok(Output {
            status: ExitStatus::default(),
            stdout: healthy_status.into_bytes(),
            stderr: Vec::new(),
        }));
        let mut manager = OpenBaoManager::new(Box::new(mock));
        manager.set_command(String::from("bao"));
        assert!(manager.check_status());
    }

    #[test]
    fn test_check_status_failure() {
        let unhealthy_status = json!({
            "Initialized": false,
            "Sealed": true
        }).to_string();
        let mut mock = MockCommandExecutor::new();
        mock.expect_execute().return_once(move |_, _, _| Ok(Output {
            status: ExitStatus::default(),
            stdout: unhealthy_status.into_bytes(),
            stderr: Vec::new(),
        }));
        let mut manager = OpenBaoManager::new(Box::new(mock));
        manager.set_command(String::from("bao"));
        assert!(!manager.check_status());
    }

    #[test]
    fn test_check_status_command_failure() {
        let mut mock = MockCommandExecutor::new();
        mock.expect_execute().return_once(move |_, _, _| Err(io::Error::new(io::ErrorKind::Other, "command failed")));
        let mut manager = OpenBaoManager::new(Box::new(mock));
        manager.set_command(String::from("bao"));
        assert!(!manager.check_status());
    }
}