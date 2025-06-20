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

use crate::init_chain::traits::{InitContext, InitHandler};
use config_manager::types::context::{ServerConfig, CONFIG};
#[allow(unused_imports)]
use env_config_parse::find_file;
use std::future::Future;
use std::pin::Pin;
use common_log::info;

#[allow(dead_code)]
const CONFIG_FILE_NAME: &str = "server_config.yaml";

#[allow(dead_code)]
#[cfg(feature = "rpm_build")]
const CONFIG_FILE_NAME_RPM: &str = "/etc/attestation_server/server_config_rpm.yaml";

#[derive(Debug)]
pub struct ConfigInitHandler {
    next: Option<Box<dyn InitHandler>>,
}

impl ConfigInitHandler {
    pub fn new() -> Self {
        ConfigInitHandler { next: None }
    }

    fn load_config(&self) -> Result<ServerConfig, String> {
        // Actual configuration loading logic
        info!("Loading configuration...");
        
        #[cfg(not(debug_assertions))]
        {
            #[cfg(feature = "docker_build")]
            let config_path = find_file(CONFIG_FILE_NAME).map(|path_buf| {
                path_buf
            }).expect("file to load configuration");

            #[cfg(feature = "rpm_build")]
            let config_path = std::path::PathBuf::from(CONFIG_FILE_NAME_RPM);
            CONFIG.initialize(config_path.to_str().ok_or("Invalid server_config path")?)?;
            Ok(CONFIG.get_instance()?.clone())
        }
        #[cfg(debug_assertions)]
        {
            let config_path = find_file("server_config_dev.yaml").expect("file to load configuration");
            CONFIG.initialize(config_path.to_str().ok_or("Invalid server_config path")?)?;
            Ok(CONFIG.get_instance()?.clone())
        }
    }
}

impl InitHandler for ConfigInitHandler {
    fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
        Box::pin(async move {
            let config = self.load_config()?;
            context.config = Some(config);

            if let Some(next) = &self.next {
                next.handle(context).await
            } else {
                Ok(())
            }
        })
    }

    fn set_next(&mut self, next: Box<dyn InitHandler>) {
        self.next = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use config_manager::types::context::CONFIG;

    fn write_yaml_config() {
        let yaml_content: String = r#"---
attestation_common:
  yaml_parse_support: "current support yaml parse"
attestation_service:
  key_management:
    vault_get_key_url: "http://attestation_mock:8081/v1/vault/get_signing_keys"
    is_require_sign: true
    key_ca_cert_path: "/etc/attestation_server/certs/km_cert.pem"
    key_cli_key_path: "/etc/attestation_server/certs/ra_client_key.pem"
    key_cli_cert_path: "/etc/attestation_server/certs/ra_client_cert.pem"
  token_management:
    jku: "jku"
    kid: "kid"
    exist_time: 600000
    iss: "iss"
    eat_profile: "eat_profile"
    mq_enabled: false
    token_topic: "ra_token_topic"
  policy:
    export_policy_file:
      - name: "tpm_boot"
        path: "/var/test_docker/app/export_policy/tpm_boot.rego"
      - name: "tpm_ima"
        path: "/var/test_docker/app/export_policy/tpm_ima.rego"
    is_verify_policy_signature: false
    single_user_policy_limit: 30
    policy_content_size_limit: 500
    query_user_policy_limit: 10
  cert:
    single_user_cert_limit: 10
  nonce:
    nonce_valid_period: 120
    nonce_bytes: 64
  plugins:
    - name: "tpm_boot"
      path: "/opt/0422/target/release/libtpm_boot_verifier.so"
    - name: "tpm_ima"
      path: "/opt/0422/target/release/libtpm_ima_verifier.so"
"#.to_string();
        let mut file = File::create("server_config.yaml").unwrap();
        let _ = file.write_all(yaml_content.as_bytes());
        let mut file = File::create("server_config_dev.yaml").unwrap();
        let _ = file.write_all(yaml_content.as_bytes());
        println!("YAML file created.");
    }

    fn delete_test_file() {
        let current_dir = std::env::current_dir().unwrap();
        let yml = current_dir.join("server_config.yaml");
        if yml.exists() {
            let _ = fs::remove_file(yml);
            println!("YAML file deleted");
        }
        let yml = current_dir.join("server_config_dev.yaml");
        if yml.exists() {
            let _ = fs::remove_file(yml);
            println!("YAML file deleted");
        }
    }

    #[tokio::test]
    async fn test_handler() {
        write_yaml_config();
        let result = ConfigInitHandler::new().handle(&mut InitContext::new()).await;
        assert!(result.is_ok());
        dbg!(CONFIG.get_instance().unwrap());
        delete_test_file();
    }
}
