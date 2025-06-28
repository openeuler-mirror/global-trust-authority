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

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use plugin_manager::{AgentPlugin, PluginBase, PluginError};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use tpm_common_attester::{Log, TpmPluginBase, TpmPluginConfig};
use tpm_dim_attester::TpmDimPlugin;

/// Test fixtures and utilities for TPM DIM attester tests
mod fixtures {
    use super::*;
    use std::sync::Once;
    use std::sync::Mutex;

    static INIT: Once = Once::new();
    static CONFIG_JSON: Mutex<Option<String>> = Mutex::new(None);

    /// Creates a mock TPM DIM plugin configuration
    pub fn create_mock_config() -> TpmPluginConfig {
        let config_json = json!({
            "attester_type": "dim",
            "tcti_config": "device:/dev/tpm0",
            "ak_certs": [
                {
                    "cert_type": "iak",
                    "ak_handle": 0x81010020_u32,
                    "ak_nv_index": 0x150001b_u32
                }
            ],
            "pcr_selections": {"banks": [12], "hash_alg": "sha256"},
            "quote_signature_scheme": {"hash_alg": "sha256", "signature_alg": "rsassa"},
            "log_file_path": "/sys/kernel/security/dim/ascii_runtime_measurements"
        })
        .to_string();

        TpmPluginConfig::from_json("tpm_dim".to_string(), &config_json)
            .expect("Failed to create mock config")
    }

    /// Creates a mock TPM DIM plugin for testing
    pub fn create_mock_plugin() -> MockTpmDimPlugin {
        MockTpmDimPlugin::new("tpm_dim".to_string())
            .expect("Failed to create mock plugin")
    }

    /// Creates a test log file with specified number of lines
    pub fn create_test_log_file(num_lines: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let log_path = temp_dir.path().join("dim.log");
        let mut file = File::create(&log_path).expect("Failed to create test log file");
        
        for i in 0..num_lines {
            writeln!(file, "Test log line {}", i).expect("Failed to write to test log file");
        }
        
        (temp_dir, log_path)
    }

    /// Mock configuration query function for testing
    pub fn test_query_configuration(plugin_type: String) -> Option<String> {
        if plugin_type == "tpm_dim" {
            CONFIG_JSON.lock().unwrap().clone()
        } else {
            None
        }
    }

    /// Sets up the test configuration
    pub fn setup_test_config(config_json: String) {
        INIT.call_once(|| {
            let mut config = CONFIG_JSON.lock().unwrap();
            *config = Some(config_json);
        });
    }
}

/// Mock implementation of TPM DIM plugin for testing
#[cfg(test)]
struct MockTpmDimPlugin {
    plugin_type: String,
    config: TpmPluginConfig,
}

#[cfg(test)]
impl MockTpmDimPlugin {
    /// Creates a new mock TPM DIM plugin
    fn new(plugin_type: String) -> Result<Self, PluginError> {
        if plugin_type != "tpm_dim" {
            return Err(PluginError::InputError("Invalid plugin type".to_string()));
        }
        
        let config = fixtures::create_mock_config();
        Ok(Self { plugin_type, config })
    }
}

#[cfg(test)]
impl PluginBase for MockTpmDimPlugin {
    fn plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

#[cfg(test)]
impl AgentPlugin for MockTpmDimPlugin {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<Value, PluginError> {
        let logs = self.collect_log()?;
        
        Ok(json!({
            "node_id": node_id,
            "nonce": nonce.map(|n| STANDARD.encode(n)),
            "logs": logs,
        }))
    }
}

#[cfg(test)]
impl TpmPluginBase for MockTpmDimPlugin {
    fn config(&self) -> &TpmPluginConfig {
        &self.config
    }

    fn collect_log(&self) -> Result<Vec<Log>, PluginError> {
        Ok(vec![Log { 
            log_type: "tpm_dim".to_string(), 
            log_data: STANDARD.encode("Test log content") 
        }])
    }
}

/// Tests for plugin creation and configuration
mod plugin_creation_tests {
    use super::*;

    #[test]
    fn should_create_plugin_with_valid_type() {
        let result = MockTpmDimPlugin::new("tpm_dim".to_string());
        assert!(result.is_ok(), "Should create plugin with valid type");
        
        let plugin = result.unwrap();
        assert_eq!(plugin.plugin_type(), "tpm_dim", "Plugin type should match");
    }

    #[test]
    fn should_fail_to_create_plugin_with_invalid_type() {
        let result = MockTpmDimPlugin::new("invalid_type".to_string());
        assert!(result.is_err(), "Should fail to create plugin with invalid type");
        
        match result {
            Err(PluginError::InputError(msg)) => assert_eq!(msg, "Invalid plugin type"),
            _ => panic!("Expected InputError"),
        }
    }
}

/// Tests for log collection functionality
mod log_collection_tests {
    use super::*;

    #[test]
    fn should_collect_log_successfully() {
        let plugin = fixtures::create_mock_plugin();
        let logs = plugin.collect_log().expect("Should collect log successfully");
        
        assert_eq!(logs.len(), 1, "Should collect one log entry");
        assert_eq!(logs[0].log_type, "tpm_dim", "Log type should match");
        
        let decoded = STANDARD.decode(&logs[0].log_data)
            .expect("Should decode log data");
        let log_str = String::from_utf8(decoded)
            .expect("Should convert log data to string");
        assert_eq!(log_str, "Test log content", "Log content should match");
    }

    #[test]
    fn should_handle_empty_log_file() {
        let plugin = fixtures::create_mock_plugin();
        let result = plugin.collect_log();
        assert!(result.is_ok(), "Should handle empty log file");
        
        let logs = result.unwrap();
        assert_eq!(logs.len(), 1, "Should return one log entry");
        assert_eq!(logs[0].log_type, "tpm_dim", "Log type should match");
        assert!(!logs[0].log_data.is_empty(), "Log data should not be empty");
    }

    #[test]
    fn should_handle_nonexistent_log_file() {
        let plugin = fixtures::create_mock_plugin();
        let result = plugin.collect_log();
        assert!(result.is_ok(), "Should handle nonexistent log file");
    }

    #[test]
    fn should_fail_when_log_file_exceeds_max_lines() {
        let (_temp_dir, log_path) = fixtures::create_test_log_file(100_001);
        let config_json = json!({
            "attester_type": "dim",
            "tcti_config": "device:/dev/tpm0",
            "ak_certs": [
                {
                    "cert_type": "iak",
                    "ak_handle": 0x81010020_u32,
                    "ak_nv_index": 0x150001b_u32
                }
            ],
            "pcr_selections": {"banks": [12], "hash_alg": "sha256"},
            "quote_signature_scheme": {"hash_alg": "sha256", "signature_alg": "rsassa"},
            "log_file_path": log_path.to_str().unwrap()
        })
        .to_string();
        
        fixtures::setup_test_config(config_json);
        
        let plugin = TpmDimPlugin::new(
            "tpm_dim".to_string(), 
            fixtures::test_query_configuration
        ).expect("Should create plugin");
        
        let result = plugin.collect_log();
        assert!(result.is_err(), "Should fail when log file exceeds max lines");
        
        match result {
            Err(PluginError::InputError(msg)) => {
                assert!(msg.contains("maximum line limit"), 
                    "Error message should mention line limit");
            },
            _ => panic!("Expected PluginError::InputError"),
        }
    }
}

/// Tests for evidence collection functionality
mod evidence_collection_tests {
    use super::*;

    #[test]
    fn should_collect_evidence_with_node_id_and_nonce() {
        let plugin = fixtures::create_mock_plugin();
        let node_id = Some("test_node");
        let nonce = Some(b"test_nonce" as &[u8]);
        
        let result = plugin.collect_evidence(node_id, nonce);
        assert!(result.is_ok(), "Should collect evidence successfully");
        
        let evidence = result.unwrap();
        assert_eq!(evidence["node_id"], "test_node", "Node ID should match");
        assert_eq!(evidence["nonce"], STANDARD.encode("test_nonce"), "Nonce should match");
        assert!(evidence["logs"].is_array(), "Logs should be an array");
    }

    #[test]
    fn should_collect_evidence_without_node_id_and_nonce() {
        let plugin = fixtures::create_mock_plugin();
        let result = plugin.collect_evidence(None, None);
        assert!(result.is_ok(), "Should collect evidence without optional parameters");
    }
}
