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

use tpm_common_attester::{TpmPluginBase, TpmPluginConfig, Log, Quote, Pcrs, PcrValue};
use plugin_manager::{AgentPlugin, PluginError, PluginBase};
use serde_json::Value;

// Mock implementation of TpmPluginBase for testing
struct MockTpmPlugin {
    config: TpmPluginConfig,
}

impl MockTpmPlugin {
    fn new() -> Self {
        // Create a minimal valid config for testing
        let config_json = r#"{
            "ak_handle": 12345,
            "ak_nv_index": 67890,
            "pcr_selections": {
                "banks": [0, 1, 2, 3],
                "hash_alg": "sha256"
            },
            "log_file_path": "/path/to/event/log",
            "tcti_config": "mssim:host=localhost,port=2321"
        }"#;
        
        let config = TpmPluginConfig::from_json("mock_plugin".to_string(), config_json)
            .expect("Failed to create mock config");
        
        Self { config }
    }
}

impl PluginBase for MockTpmPlugin {
    fn plugin_type(&self) -> &str {
        &self.config.plugin_type
    }
}

impl AgentPlugin for MockTpmPlugin {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<Value, PluginError> {
        self.collect_evidence_impl(node_id, nonce)
    }
}

impl TpmPluginBase for MockTpmPlugin {
    fn config(&self) -> &TpmPluginConfig {
        &self.config
    }
    
    // Override the default implementations for testing
    fn collect_aik(&self, _node_id: &str) -> Result<String, PluginError> {
        Ok("mock_ak_cert".to_string())
    }
    
    fn collect_pcrs(&self) -> Result<Pcrs, PluginError> {
        Ok(Pcrs {
            hash_alg: "sha256".to_string(),
            pcr_values: vec![
                PcrValue {
                    pcr_index: 0,
                    pcr_value: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                },
                PcrValue {
                    pcr_index: 1,
                    pcr_value: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
                },
            ],
        })
    }
    
    fn collect_quote(&self, _nonce: &[u8]) -> Result<Quote, PluginError> {
        Ok(Quote {
            quote_data: "mock_quote_data".to_string(),
            signature: "mock_signature".to_string(),
        })
    }
    
    fn collect_log(&self) -> Result<Vec<Log>, PluginError> {
        Ok(vec![
            Log {
                log_type: "TcgEventLog".to_string(),
                log_data: "mock_event_log_data".to_string(),
            },
        ])
    }
}

#[test]
fn test_collect_evidence_impl() {
    let plugin = MockTpmPlugin::new();
    
    // Test with valid inputs
    let result = plugin.collect_evidence(Some("test_node"), Some("123456".as_bytes()));
    assert!(result.is_ok());
    
    let evidence_json = result.unwrap();
    assert!(evidence_json.is_object());
    assert_eq!(evidence_json["ak_cert"], "mock_ak_cert");
    assert_eq!(evidence_json["quote"]["quote_data"], "mock_quote_data");
    assert_eq!(evidence_json["quote"]["signature"], "mock_signature");
    assert_eq!(evidence_json["pcrs"]["hash_alg"], "sha256");
    assert_eq!(evidence_json["pcrs"]["pcr_values"].as_array().unwrap().len(), 2);
    assert_eq!(evidence_json["logs"].as_array().unwrap().len(), 1);
    assert_eq!(evidence_json["logs"][0]["log_type"], "TcgEventLog");
    
    // Test with missing node_id
    let result = plugin.collect_evidence(None, Some("123456".as_bytes()));
    assert!(result.is_err());
    match result {
        Err(PluginError::InputError(_)) => {}, // Expected error
        _ => panic!("Expected InputError for missing node_id"),
    }
}

#[test]
fn test_plugin_type() {
    let plugin = MockTpmPlugin::new();
    assert_eq!(plugin.plugin_type(), "mock_plugin");
}

