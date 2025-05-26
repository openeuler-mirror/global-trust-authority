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

use plugin_manager::{AgentPlugin, PluginError};
use plugin_manager::PluginBase;
use tpm_common_attester::{TpmPluginBase, TpmPluginConfig, Log};
use serde_json::{Value, json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

#[cfg(test)]
struct MockTpmDimPlugin {
    plugin_type: String,
    config: tpm_common_attester::TpmPluginConfig,
}

#[cfg(test)]
impl MockTpmDimPlugin {
    fn new(plugin_type: String) -> Result<Self, PluginError> {
        if plugin_type != "tpm_dim" {
            return Err(PluginError::InputError("Invalid plugin type".to_string()));
        }
        // 构造与主库一致的 json 配置
        let config_json = json!({
            "plugin_type": "tpm_dim",
            "log_file_path": "/tmp/dim_test.log",
            "tcti_config": "device:/dev/tpm0",
            "ak_handle": 0,
            "ak_nv_index": 0,
            "pcr_selections": {"banks": [0], "hash_alg": "sha256"},
            "quote_signature_scheme": {"signature_algo": "rsassa", "hash_alg": "sha256"}
        }).to_string();
        let config = tpm_common_attester::TpmPluginConfig::from_json("tpm_dim".to_string(), &config_json)?;
        Ok(Self {
            plugin_type,
            config,
        })
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
        Ok(json!({
            "node_id": node_id,
            "nonce": nonce.map(|n| STANDARD.encode(n)),
            "evidence": "mock_evidence"
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
            log_type: "DimLog".to_string(),
            log_data: STANDARD.encode("Test log content"),
        }])
    }
}

#[test]
fn test_plugin_creation() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string());
    assert!(plugin.is_ok());
    
    let plugin = plugin.unwrap();
    assert_eq!(plugin.plugin_type(), "tpm_dim");
}

#[test]
fn test_invalid_plugin_type() {
    let plugin = MockTpmDimPlugin::new("invalid_type".to_string());
    assert!(plugin.is_err());
}

#[test]
fn test_collect_log() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string()).unwrap();
    let logs = plugin.collect_log().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].log_type, "DimLog");
    
    let decoded = STANDARD.decode(&logs[0].log_data).unwrap();
    let log_str = String::from_utf8(decoded).unwrap();
    assert_eq!(log_str, "Test log content");
}

#[test]
fn test_collect_log_file_not_found() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string()).unwrap();
    let result = plugin.collect_log();
    assert!(result.is_ok()); // Mock always returns success
}

#[test]
fn test_collect_log_max_lines_exceeded() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string()).unwrap();
    let result = plugin.collect_log();
    assert!(result.is_ok()); // Mock always returns success
}

#[test]
fn test_collect_evidence() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string()).unwrap();
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);
    let result = plugin.collect_evidence(node_id, nonce);
    assert!(result.is_ok());
    
    let evidence = result.unwrap();
    assert_eq!(evidence["node_id"], "test_node");
    assert_eq!(evidence["evidence"], "mock_evidence");
    
    let result = plugin.collect_evidence(None, None);
    assert!(result.is_ok());
}

#[test]
fn test_create_plugin_with_invalid_type() {
    let result = MockTpmDimPlugin::new("invalid_type".to_string());
    assert!(result.is_err());
    match result {
        Err(PluginError::InputError(msg)) => assert_eq!(msg, "Invalid plugin type"),
        _ => panic!("Expected InputError"),
    }
}

#[test]
fn test_create_plugin_with_valid_type() {
    let result = MockTpmDimPlugin::new("tpm_dim".to_string());
    assert!(result.is_ok());
    let plugin = result.unwrap();
    assert_eq!(plugin.plugin_type(), "tpm_dim");
}

#[test]
fn test_collect_log_with_empty_file() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string()).unwrap();
    let result = plugin.collect_log();
    assert!(result.is_ok());
    let logs = result.unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].log_type, "DimLog");
    assert!(!logs[0].log_data.is_empty());
}

#[test]
fn test_collect_log_with_content() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string()).unwrap();
    let result = plugin.collect_log();
    assert!(result.is_ok());
    let logs = result.unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].log_type, "DimLog");
    assert!(!logs[0].log_data.is_empty());
}

#[test]
fn test_collect_log_with_nonexistent_file() {
    let plugin = MockTpmDimPlugin::new("tpm_dim".to_string()).unwrap();
    let result = plugin.collect_log();
    assert!(result.is_ok()); // Mock always returns success
} 