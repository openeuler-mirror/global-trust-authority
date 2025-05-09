#[cfg(test)]
mod tests {
    use key_managerd::models::cipher_models::PutCipherReq;
    use std::env;
    use std::process::Command;
    use validator::Validate;

    const TESTS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/");

    fn test_setup() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            Command::new("sh").arg(format!("{}generate_test_key_file.sh", TESTS_PATH))
                .status().expect("Failed to run generate test key file script");
            println!("Run generate test key file script successfully");
        });
    }

    #[test]
    fn validate_rsa_3027_success() {
        test_setup();
        let content = std::fs::read_to_string(format!("{}testdata/rsa_3072.key", TESTS_PATH))
            .expect("Failed to read generated key");
        let req = PutCipherReq {
            key_name: "FSK".into(),
            encoding: "pem".into(),
            algorithm: "rsa_3072".into(),
            private_key: content,
            key_file: "".into(),
        };

        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_rsa_3027_failure() {
        test_setup();
        let content = std::fs::read_to_string(format!("{}testdata/invalid.key", TESTS_PATH))
            .expect("Failed to read generated key");
        let req = PutCipherReq {
            key_name: "FSK".into(),
            encoding: "pem".into(),
            algorithm: "rsa_3072".into(),
            private_key: content,
            key_file: "".into(),
        };

        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_rsa_3027_from_file_success() {
        test_setup();
        let req = PutCipherReq {
            key_name: "FSK".into(),
            encoding: "pem".into(),
            algorithm: "rsa_3072".into(),
            private_key: "".into(),
            key_file: "./testdata/rsa_3072.key".into(),
        };

        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_rsa_3027_from_file_failure() {
        test_setup();
        let req = PutCipherReq {
            key_name: "FSK".into(),
            encoding: "pem".into(),
            algorithm: "rsa_3072".into(),
            private_key: "".into(),
            key_file: "./testdata/invalid.key".into(),
        };

        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_ec_success() {
        test_setup();
        let content =
            std::fs::read_to_string(format!("{}testdata/ec.key", TESTS_PATH))
                .expect("Failed to read generated key");
        let req = PutCipherReq {
            key_name: "FSK".into(),
            encoding: "pem".into(),
            algorithm: "ec".into(),
            private_key: content,
            key_file: "".into(),
        };

        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_ec_failure() {
        test_setup();
        let content = std::fs::read_to_string(format!("{}testdata/invalid.key", TESTS_PATH))
            .expect("Failed to read generated key");
        let req = PutCipherReq {
            key_name: "FSK".into(),
            encoding: "pem".into(),
            algorithm: "ec".into(),
            private_key: content,
            key_file: "".into(),
        };

        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_sm2_failure() {
        test_setup();
        let content = std::fs::read_to_string(format!("{}testdata/invalid.key", TESTS_PATH))
            .expect("Failed to read generated key");
        let req = PutCipherReq {
            key_name: "FSK".into(),
            encoding: "pem".into(),
            algorithm: "sm2".into(),
            private_key: content,
            key_file: "".into(),
        };

        assert!(req.validate().is_err());
    }

    // 混合错误场景测试
    #[test]
    fn multiple_errors_should_be_reported() {
        test_setup();
        let req = PutCipherReq {
            key_name: "WRONG".into(),
            encoding: "DER".into(),
            algorithm: "AES".into(),
            private_key: "".into(),
            key_file: "".into(),
        };

        let errors = req.validate().unwrap_err();
        assert_eq!(errors.field_errors().len(), 3);
    }
}
