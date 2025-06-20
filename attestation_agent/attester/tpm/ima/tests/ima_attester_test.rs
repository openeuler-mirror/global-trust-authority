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

use tpm_ima_attester::TpmImaPlugin;
use plugin_manager::PluginError;
use serde_json;

/// Test configuration for the IMA plugin
fn mock_ima_configuration(_plugin_type: String) -> Option<String> {
    let config = serde_json::json!({
        "attester_type": "ima",
        "tcti_config": "device:/dev/tpm0",
        "ak_certs": [{"cert_type": "aik", "ak_handle": 0x81010020_u32, "ak_nv_index": 0x150001b_u32}],
        "pcr_selections": {"banks": [10], "hash_alg": "sha256"},
        "quote_signature_scheme": {"hash_alg": "sha256", "signature_alg": "rsassa"},
        "log_file_path": "/sys/kernel/security/ima/ascii_runtime_measurements",
        "template_name": "ima-ng",
        "ascii_runtime_measurements": true,
        "quote_hash_algo": "sha256"
    });
    Some(config.to_string())
}

/// Test configuration for invalid JSON
fn mock_invalid_json_configuration(_plugin_type: String) -> Option<String> {
    Some("{ invalid json }".to_string())
}

/// Test configuration with missing ak_handle
fn mock_missing_ak_handle_configuration(_plugin_type: String) -> Option<String> {
    let config = serde_json::json!({
        "attester_type": "ima",
        "tcti_config": "device:/dev/tpm0",
        // ak_handle is missing
        "ak_certs": [{"cert_type": "aik", "ak_nv_index": 0x150001b_u32}],
        "pcr_selections": {"banks": [10], "hash_alg": "sha256"},
        "log_file_path": "/sys/kernel/security/ima/ascii_runtime_measurements",
        "template_name": "ima-ng",
        "ascii_runtime_measurements": true,
        "quote_hash_algo": "sha256"
    });
    Some(config.to_string())
}

/// Test configuration with missing ak_nv_index
fn mock_missing_ak_nv_index_configuration(_plugin_type: String) -> Option<String> {
    let config = serde_json::json!({
        "attester_type": "ima",
        "tcti_config": "device:/dev/tpm0",
        "ak_certs": [{"cert_type": "aik", "ak_handle": 0x81010020_u32}],
        // ak_nv_index is missing
        "pcr_selections": {"banks": [10], "hash_alg": "sha256"},
        "log_file_path": "/sys/kernel/security/ima/ascii_runtime_measurements",
        "template_name": "ima-ng",
        "ascii_runtime_measurements": true,
        "quote_hash_algo": "sha256"
    });
    Some(config.to_string())
}

/// Test configuration with missing pcr_selections
fn mock_missing_pcr_selections_configuration(_plugin_type: String) -> Option<String> {
    let config = serde_json::json!({
        "attester_type": "ima",
        "tcti_config": "device:/dev/tpm0",
        "ak_certs": [{"cert_type": "aik", "ak_handle": 0x81010020_u32, "ak_nv_index": 0x150001b_u32}],
        // pcr_selections is missing
        "log_file_path": "/sys/kernel/security/ima/ascii_runtime_measurements",
        "template_name": "ima-ng",
        "ascii_runtime_measurements": true,
        "quote_hash_algo": "sha256"
    });
    Some(config.to_string())
}

/// Test configuration with missing log_file_path
fn mock_missing_log_file_path_configuration(_plugin_type: String) -> Option<String> {
    let config = serde_json::json!({
        "attester_type": "ima",
        "tcti_config": "device:/dev/tpm0",
        "ak_certs": [{"cert_type": "aik", "ak_handle": 0x81010020_u32, "ak_nv_index": 0x150001b_u32}],
        "pcr_selections": {"banks": [10], "hash_alg": "sha256"},
        // log_file_path is missing
        "template_name": "ima-ng",
        "ascii_runtime_measurements": true,
        "quote_hash_algo": "sha256"
    });
    Some(config.to_string())
}

/// Test configuration that returns None
fn mock_none_configuration(_plugin_type: String) -> Option<String> {
    None
}

/* 
* Test the TpmAgentPlugin implementation, not runnable without manual environment configuration and commented out by default
*/
// #[test]
// fn test_tpm_ima_plugin() {
//     // Create a new plugin with the mock configuration
//     let plugin = TpmImaPlugin::new(String::from("tpm_ima"), mock_ima_configuration)
//         .expect("Failed to create TpmImaPlugin");

//     let result = plugin.collect_evidence(Some("test-node-id"), Some("123456".as_bytes()));

//     // Check that the result is Ok
//     assert!(result.is_ok(), "collect_evidence failed: {:?}", result.err());

//     // Print the result
//     println!("Collect evidence result: {}", result.unwrap());
// }

#[test]
fn test_tpm_ima_plugin_with_valid_configuration() {
    // Create a new plugin with the mock configuration
    let plugin = TpmImaPlugin::new(String::from("tpm_ima"), mock_ima_configuration);

    // Check that plugin creation is successful
    assert!(plugin.is_ok());
}

#[test]
fn test_missing_plugin_configuration() {
    // Create a new plugin with a non-existent plugin type
    let plugin_result = TpmImaPlugin::new(String::from("tpm_ima"), mock_none_configuration);

    // Check that plugin creation fails with the expected error
    assert!(plugin_result.is_err());
    if let Err(PluginError::InternalError(msg)) = plugin_result {
        assert_eq!(msg, "Plugin configuration not found");
    } else {
        panic!("Expected InternalError with 'Plugin configuration not found', got {:?}", plugin_result);
    }
}

#[test]
fn test_invalid_json_configuration() {
    // Create a new plugin with invalid JSON configuration
    let plugin_result = TpmImaPlugin::new(String::from("tpm_ima"), mock_invalid_json_configuration);

    // Check that plugin creation fails with the expected error
    assert!(plugin_result.is_err());
    if let Err(PluginError::InternalError(msg)) = plugin_result {
        assert!(msg.starts_with("Failed to parse plugin configuration as JSON"));
    } else {
        panic!("Expected InternalError with 'Failed to parse plugin configuration as JSON', got {:?}", plugin_result);
    }
}

#[test]
fn test_missing_ak_handle() {
    // Create a new plugin with missing ak_handle configuration
    let plugin_result = TpmImaPlugin::new(String::from("tpm_ima"), mock_missing_ak_handle_configuration);

    // Check that plugin creation fails with the expected error
    assert!(plugin_result.is_err());
    if let Err(PluginError::InternalError(msg)) = plugin_result {
        assert_eq!(msg, "AK handle not found or invalid");
    } else {
        panic!("Expected InternalError with 'AK handle not found or invalid', got {:?}", plugin_result);
    }
}

#[test]
fn test_missing_ak_nv_index() {
    // Create a new plugin with missing ak_nv_index configuration
    let plugin_result = TpmImaPlugin::new(String::from("tpm_ima"), mock_missing_ak_nv_index_configuration);

    // Check that plugin creation fails with the expected error
    assert!(plugin_result.is_err());
    if let Err(PluginError::InternalError(msg)) = plugin_result {
        assert_eq!(msg, "AK NV index not found or invalid");
    } else {
        panic!("Expected InternalError with 'AK NV index not found or invalid', got {:?}", plugin_result);
    }
}

#[test]
fn test_missing_pcr_selections() {
    // Create a new plugin with missing pcr_selections configuration
    let plugin_result = TpmImaPlugin::new(String::from("tpm_ima"), mock_missing_pcr_selections_configuration);

    // Check that plugin creation fails with the expected error
    assert!(plugin_result.is_err());
    if let Err(PluginError::InternalError(msg)) = plugin_result {
        assert_eq!(msg, "PCR selections not found");
    } else {
        panic!("Expected InternalError with 'PCR selections not found', got {:?}", plugin_result);
    }
}

#[test]
fn test_missing_log_file_path() {
    // Create a new plugin with missing log_file_path configuration
    let plugin_result = TpmImaPlugin::new(String::from("tpm_ima"), mock_missing_log_file_path_configuration);

    // Check that plugin creation fails with the expected error
    assert!(plugin_result.is_err());
    if let Err(PluginError::InternalError(msg)) = plugin_result {
        assert_eq!(msg, "Log file path not found");
    } else {
        panic!("Expected InternalError with 'Log file path not found', got {:?}", plugin_result);
    }
}
