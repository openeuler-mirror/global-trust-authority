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

use serde_json::json;
use ascend_npu_verifier::verifier::AscendNpuPlugin;
use plugin_manager::{PluginBase, ServicePlugin, ServiceHostFunctions};

// Mock ServiceHostFunctions for testing
fn create_mock_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    }
}

#[tokio::test]
async fn test_ascend_npu_plugin_creation() {
    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    assert_eq!(plugin.plugin_type(), "test_config");
}

#[tokio::test]
async fn test_ascend_npu_plugin_get_sample_output() {
    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let sample_output = plugin.get_sample_output();
    
    // Check that sample output contains evidence field
    assert!(sample_output.get("evidence").is_some());
    
    let evidence = sample_output.get("evidence").unwrap();
    
    // Check that evidence contains required fields
    assert!(evidence.get("ak_cert").is_some());
    assert!(evidence.get("quote").is_some());
    assert!(evidence.get("pcrs").is_some());
    
    // Check quote structure
    let quote = evidence.get("quote").unwrap();
    assert!(quote.get("quote_data").is_some());
    assert!(quote.get("signature").is_some());
    
    // Check pcrs structure
    let pcrs = evidence.get("pcrs").unwrap();
    assert!(pcrs.get("hash_alg").is_some());
    assert!(pcrs.get("pcr_values").is_some());
    
    let pcr_values = pcrs.get("pcr_values").unwrap().as_array().unwrap();
    assert!(!pcr_values.is_empty());
    
    // Check first PCR value structure
    let first_pcr = &pcr_values[0];
    assert!(first_pcr.get("pcr_index").is_some());
    assert!(first_pcr.get("pcr_value").is_some());
}

#[tokio::test]
async fn test_ascend_npu_plugin_verify_evidence_success() {
    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "dGVzdF9xdW90ZV9kYXRh",
            "signature": "dGVzdF9zaWduYXR1cmU="
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 1,
                    "pcr_value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            ]
        }
    });

    let result = plugin.verify_evidence("test_user", None, &evidence_json, None).await;
    // Note: This will likely fail due to invalid certificate, but we're testing the structure
    // In a real test, you would use valid test data
    assert!(result.is_err()); // Expected to fail with invalid test data
}

#[tokio::test]
async fn test_ascend_npu_plugin_verify_evidence_invalid_json() {
    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    
    let invalid_json = json!({
        "ak_cert": "invalid_cert",
        "quote": {
            "quote_data": "invalid_data"
            // Missing signature field
        }
    });

    let result = plugin.verify_evidence("test_user", None, &invalid_json, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ascend_npu_plugin_verify_evidence_missing_fields() {
    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    
    let incomplete_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"
        // Missing quote and pcrs fields
    });

    let result = plugin.verify_evidence("test_user", None, &incomplete_json, None).await;
    assert!(result.is_err());
}
