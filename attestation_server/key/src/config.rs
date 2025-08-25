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
use serde::Deserialize;
#[allow(unused_imports)]
use std::env;
use std::fmt::Debug;
use std::sync::{Mutex, OnceLock};
#[allow(unused_imports)]
use env_config_parse::find_file;
use config_manager::types::context::CONFIG;

pub static CONFIG_CACHE: OnceLock<Mutex<YamlConfig>> = OnceLock::new();

#[automock]
pub trait ConfigLoader: Debug {
    fn load_config(&self) -> Option<Box<dyn Config>>;
}

#[derive(Debug)]
pub struct YamlConfigLoader;

impl ConfigLoader for YamlConfigLoader {
    fn load_config(&self) -> Option<Box<dyn Config>> {
        #[cfg(not(debug_assertions))]
        let config = CONFIG_CACHE.get_or_init(|| {
            let yml_config = CONFIG.get_instance().expect("Failed to obtain the YAML configuration").clone();
            Mutex::new(
                YamlConfig {
                    vault_get_key_url: yml_config.attestation_service.key_management.vault_get_key_url,
                    is_require_sign: yml_config.attestation_service.key_management.is_require_sign,
                    key_ca_cert_path: yml_config.attestation_service.key_management.key_ca_cert_path,
                    key_cli_key_path: yml_config.attestation_service.key_management.key_cli_key_path,
                    key_cli_cert_path: yml_config.attestation_service.key_management.key_cli_cert_path
                }
            )
        });
        #[cfg(debug_assertions)]
        let config = CONFIG_CACHE.get_or_init(|| {
            let env_file = find_file(".env.dev")
                .map(|file| file.to_str().unwrap().to_string()).unwrap_or("./.env.dev".to_string());
            dotenv::from_filename(env_file).ok();
            let yml_config = CONFIG.get_instance().expect("Failed to obtain the YAML configuration").clone();
            let vault_get_key_url = yml_config.attestation_service.key_management.vault_get_key_url;
            let is_require_sign = yml_config.attestation_service.key_management.is_require_sign;
            let key_ca_cert_path = yml_config.attestation_service.key_management.key_ca_cert_path;
            let key_cli_key_path = yml_config.attestation_service.key_management.key_cli_key_path;
            let key_cli_cert_path = yml_config.attestation_service.key_management.key_cli_cert_path;
            Mutex::new(
                YamlConfig {
                    vault_get_key_url,
                    is_require_sign,
                    key_ca_cert_path,
                    key_cli_key_path,
                    key_cli_cert_path
                }
            )
        });
        Some(Box::new(config.lock().unwrap().clone()))
    }
}

pub trait Config: Debug {
    fn vault_get_key_url(&self) -> String;
    fn is_require_sign(&self) -> bool;
    fn key_ca_cert_path(&self) -> String;
    fn key_cli_key_path(&self) -> String;
    fn key_cli_cert_path(&self) -> String;
}

#[derive(Deserialize, Debug, Clone)]
pub struct YamlConfig {
    pub vault_get_key_url: String,
    pub is_require_sign: bool,
    pub key_ca_cert_path: String,
    pub key_cli_key_path: String,
    pub key_cli_cert_path: String,
}

impl Config for YamlConfig {
    fn vault_get_key_url(&self) -> String {
        self.vault_get_key_url.clone()
    }

    fn is_require_sign(&self) -> bool {
        self.is_require_sign.clone()
    }

    fn key_ca_cert_path(&self) -> String {
        self.key_ca_cert_path.clone()
    }

    fn key_cli_key_path(&self) -> String {
        self.key_cli_key_path.clone()
    }

    fn key_cli_cert_path(&self) -> String {
        self.key_cli_cert_path.clone()
    }
}

#[cfg(test)]
#[allow(warnings)]
mod tests {
    use super::*;

    // Test simulated config path handling
    #[test]
    fn test_config_loader_path_resolution() {
        let current_exe = env::current_exe().ok().unwrap();
        let yml_dir = current_exe.parent().unwrap().parent().unwrap().parent().unwrap();
        // Create temporary directory structure to simulate project layout
        std::fs::create_dir_all(&yml_dir).unwrap();

        // Create mock config file
        let config_content = r#"
attestation_service:
  key_management:
    vault_get_key_url: "https://mock.vault.com/api"
    is_require_sign: true
    key_ca_cert_path: "test"
    key_cli_key_path: "test"
    key_cli_cert_path: "test"
  token_management:
    jku: "jku"
    kid: "kid"
    exist_time: 600000
    iss: "iss"
    eat_profile: "test"
    mq_enabled: false
    token_topic: "test"
    token_signing_algorithm: "PS256"
  policy:
    export_policy_file:
      - name: "tpm_boot"
        path: "/var/test_docker/app/export_policy/tpm_boot.rego"
      - name: "tpm_ima"
        path: "test"
    is_verify_policy_signature: false
    single_user_policy_limit: 30
    policy_content_size_limit: 500
    query_user_policy_limit: 10
  cert:
    single_user_cert_limit: 10
  nonce:
    nonce_valid_period: 130
    nonce_bytes: 64
  plugins:
    - name: "tpm_boot"
      path: "test"
    - name: "tpm_ima"
      path: "/usr/local/lib/libtpm_ima_verifier.so"
        "#;
        std::fs::write(yml_dir.join("server_config.yaml"), config_content).unwrap();
        CONFIG.initialize(yml_dir.join("server_config.yaml")).unwrap();
        // Set current executable path environment
        let loader = YamlConfigLoader;

        // Verify config loading
        let config = loader.load_config().expect("Should load config");
        assert_eq!(
            config.vault_get_key_url(),
            "https://mock.vault.com/api"
        );
    }

    // Test YamlConfig struct functionality
    #[test]
    fn test_yaml_config_implementation() {
        let yaml_config = YamlConfig {
            vault_get_key_url: "https://test.url".to_string(),
            is_require_sign: true,
            key_ca_cert_path: "String".to_string(),
            key_cli_key_path: "String".to_string(),
            key_cli_cert_path: "String".to_string(),
        };
        let config: &dyn Config = &yaml_config;
        assert_eq!(config.vault_get_key_url(), "https://test.url");
    }

    // Use mock to test ConfigLoader trait
    #[test]
    fn test_mock_config_loader() {
        let mut mock_loader = MockConfigLoader::new();

        // Set mock expectations
        mock_loader.expect_load_config()
            .returning(|| Some(Box::new(YamlConfig {
                vault_get_key_url: "mock://test.url".to_string(),
                is_require_sign: false,
                key_ca_cert_path: "String".to_string(),
                key_cli_key_path: "String".to_string(),
                key_cli_cert_path: "String".to_string(),
            })));

        // Verify mock behavior
        let config = mock_loader.load_config().unwrap();
        assert_eq!(config.vault_get_key_url(), "mock://test.url");
    }
}
