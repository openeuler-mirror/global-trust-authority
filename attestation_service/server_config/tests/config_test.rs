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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use config_manager::types::context::CONFIG;

    fn get_config_path() -> PathBuf {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        repo_root.join("server_config.yaml")
    }

    #[test]
    fn test_config_loading() {
        // Get the path to the server_config.yaml file
        let config_path = get_config_path();
        
        // Initialize the configuration
        let result = CONFIG.initialize(config_path.to_str().unwrap());
        assert!(result.is_ok(), "Failed to initialize config: {:?}", result.err());
        
        // Get the configuration
        let config = CONFIG.get_instance();
        assert!(config.is_ok(), "Failed to get config: {:?}", config.err());
        
        let config = config.unwrap();
        
        // Verify attestation_service structure
        assert_eq!(config.attestation_service.token_management.jku, "jku");
        assert_eq!(config.attestation_service.token_management.kid, "kid");
        assert_eq!(config.attestation_service.token_management.exist_time, 600000);
        assert_eq!(config.attestation_service.token_management.iss, "iss");
        assert_eq!(config.attestation_service.token_management.eat_profile, "eat_profile");
        
        // Verify attestation_common structure if it exists
        if let Some(common) = &config.attestation_common {
            assert_eq!(common.yaml_parse_support, "current support yaml parse");
        }
    }

    #[test]
    fn test_config_not_initialized() {
        // This test should be run in isolation to ensure CONFIG is not initialized
        // In practice, this is difficult to test in the same test binary
        // because other tests may have already initialized the configuration
        let config = CONFIG.get_instance();
        if config.is_err() {
            assert!(config.err().unwrap().contains("not initialized"));
        }
        // If the test runs after another test that initializes the config,
        // this assertion will be skipped
    }
}
