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

use tpm_common_attester::TpmPluginConfig;

#[test]
fn test_config_from_json_valid() {
    // Create a valid JSON configuration
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            },
            {
                "cert_type": "lak",
                "ak_handle": 1122,
                "ak_nv_index": 3344
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "log_file_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0"
    }"#;
    
    // Parse the configuration
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);

    // Verify the result is Ok
    assert!(result.is_ok());
    
    // Verify the parsed configuration values
    let config = result.unwrap();
    assert_eq!(config.plugin_type, "test_plugin");
    assert_eq!(config.ak_certs[0].cert_type, "iak");
    assert_eq!(config.ak_certs[0].ak_handle, 12345);
    assert_eq!(config.ak_certs[0].ak_nv_index, 67890);
    assert_eq!(config.ak_certs[1].cert_type, "lak");
    assert_eq!(config.ak_certs[1].ak_handle, 1122);
    assert_eq!(config.ak_certs[1].ak_nv_index, 3344);
    assert_eq!(config.log_file_path, "/path/to/event/log");
    assert_eq!(config.pcr_selection.hash_alg, "sha256");
    assert_eq!(config.pcr_selection.banks, vec![0, 1, 2, 3]);
    assert!(config.quote_signature_scheme.is_none());
}

#[test]
fn test_config_with_signature_scheme() {
    // Create a JSON configuration with signature scheme
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "log_file_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0",
        "quote_signature_scheme": {
            "signature_alg": "rsassa",
            "hash_alg": "sha256"
        }
    }"#;
    
    // Parse the configuration
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    
    // Verify the result is Ok
    assert!(result.is_ok());
    
    // Verify the parsed configuration values
    let config = result.unwrap();
    assert_eq!(config.plugin_type, "test_plugin");
    
    // Verify signature scheme
    let signature_scheme = config.quote_signature_scheme.unwrap();
    assert_eq!(signature_scheme.signature_alg, "rsassa");
    assert_eq!(signature_scheme.hash_alg, "sha256");
}

#[test]
fn test_config_with_invalid_signature_scheme() {
    // Missing hash_alg in signature scheme
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "log_file_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0",
        "quote_signature_scheme": {
            "signature_alg": "rsassa"
        }
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
    
    // Missing signature_alg in signature scheme
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "log_file_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0",
        "quote_signature_scheme": {
            "hash_alg": "sha256"
        }
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
    
    // Invalid signature scheme format (not an object)
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "log_file_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0",
        "quote_signature_scheme": "invalid"
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
}

#[test]
fn test_missing_ak_handle() {
    // Missing ak_handle
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_nv_index": 67890
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "event_log_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0"
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
}

#[test]
fn test_missing_ak_nv_index() {
    // Missing ak_nv_index
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "event_log_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0"
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
}

#[test]
fn test_missing_pcr_selections() {
    // Missing pcr_selections
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            }
        ],
        "event_log_path": "/path/to/event/log",
        "tcti_config": "device:/dev/tpmrm0"
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
}

#[test]
fn test_missing_log_path() {
    // Missing log path
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "tcti_config": "device:/dev/tpmrm0"
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
}

#[test]
fn test_missing_tcti_config() {
    // Missing tcti_config
    let config_json = r#"{
        "ak_certs": [
            {
                "cert_type": "iak",
                "ak_handle": 12345,
                "ak_nv_index": 67890
            }
        ],
        "pcr_selections": {
            "banks": [0, 1, 2, 3],
            "hash_alg": "sha256"
        },
        "log_file_path": "/path/to/event/log"
    }"#;
    
    let result = TpmPluginConfig::from_json("test_plugin".to_string(), config_json);
    assert!(result.is_err());
}

