#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::process::{ExitStatus, Output};
    use key_managerd::key_manager::base_key_manager::{CommandExecutor, MockCommandExecutor, PrivateKey};

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
            "test_key".to_string(),
            "RSA".to_string(),
            "PEM".to_string()
        );
        assert_eq!(key.version, "v1");
        assert_eq!(key.private_key, "test_key");
        assert_eq!(key.algorithm, "RSA");
        assert_eq!(key.encoding, "PEM");
    }

    #[test]
    fn test_command_executor_mock() {
        let mut mock = MockCommandExecutor::new();

        // 模拟成功的命令执行
        mock.expect_run().return_once(move |_, _, _| Ok(Output {
                status: ExitStatus::default(),
                stdout: b"success".to_vec(),
                stderr: Vec::new(),
            }));
        let vec:Vec<String> = vec![String::from("status")];
        let result = mock.run("bao", &vec, &HashMap::new());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().stdout, b"success");
    }
}