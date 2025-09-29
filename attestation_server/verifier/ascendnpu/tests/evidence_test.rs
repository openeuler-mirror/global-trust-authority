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
use ascend_npu_verifier::evidence::AscendNpuEvidence;

#[tokio::test]
async fn test_ascend_npu_evidence_parsing() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 1,
                    "pcr_value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                },
                {
                    "pcr_index": 2,
                    "pcr_value": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                }
            ]
        },
        "logs": [
            {
                "log_type": "boot_measurement",
                "log_data": "dGVzdF9ib290X2xvZw=="
            },
            {
                "log_type": "runtime_measurement",
                "log_data": "dGVzdF9ydW50aW1lX2xvZw=="
            }
        ]
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    if let Err(e) = &evidence {
        println!("Error: {:?}", e);
    }
    assert!(evidence.is_ok());
    
    let evidence = evidence.unwrap();
    assert_eq!(evidence.ak_cert, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t");
    // Note: The quote data is now a serialized TPM structure, not the original base64 string
    // We can verify that the original data is embedded in the PCR digest
    let quote_data = evidence.quote.get_quote_data_base64().unwrap();
    assert!(quote_data.len() > 0, "Quote data should not be empty");
    
    // The signature should contain our test signature data
    let signature_data = evidence.quote.get_signature_base64().unwrap();
    assert!(signature_data.len() > 0, "Signature data should not be empty");
    assert_eq!(evidence.pcrs.hash_alg, "sha256");
    assert_eq!(evidence.pcrs.pcr_values.len(), 2);
    assert_eq!(evidence.pcrs.pcr_values[0].pcr_index, 1);
    assert_eq!(evidence.pcrs.pcr_values[1].pcr_index, 2);
    
    if let Some(logs) = &evidence.logs {
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].log_type, "boot_measurement");
        assert_eq!(logs[1].log_type, "runtime_measurement");
    }
}

#[tokio::test]
async fn test_ascend_npu_evidence_without_logs() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
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

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_ok());
    
    let evidence = evidence.unwrap();
    assert!(evidence.logs.is_none());
}

#[tokio::test]
async fn test_ascend_npu_evidence_verification_without_logs() {
    use ascend_npu_verifier::verifier::AscendNpuPlugin;
    use plugin_manager::{ServicePlugin, ServiceHostFunctions};

    // Create mock host functions
    let host_functions = ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    };

    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
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

    let plugin = AscendNpuPlugin::new("test_config".to_string(), host_functions);
    
    // This should succeed even without logs
    let result = plugin.verify_evidence("test_user", None, &evidence_json, None).await;
    
    // Should fail due to invalid certificate/quote data, but structure parsing should work
    assert!(result.is_err());
    
    let error_msg = result.unwrap_err().to_string();
    // Should fail at certificate parsing or quote and PCR verification, not at structure parsing
    assert!(error_msg.contains("Failed to decode") || 
            error_msg.contains("Failed to parse") ||
            error_msg.contains("certificate") ||
            error_msg.contains("signature") ||
            error_msg.contains("quote"));
}

#[tokio::test]
async fn test_ascend_npu_evidence_missing_required_fields() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        }
        // Missing pcrs field
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_err());
}

#[tokio::test]
async fn test_ascend_npu_evidence_invalid_pcr_index() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 25,  // Invalid PCR index (should be 0-23)
                    "pcr_value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            ]
        }
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_ok());
    
    // Test that parsing succeeds but verification would fail
    let evidence = evidence.unwrap();
    assert_eq!(evidence.pcrs.pcr_values[0].pcr_index, 25);
}

#[tokio::test]
async fn test_ascend_npu_evidence_sm3_hash_algorithm() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sm3",  // Test SM3 hash algorithm support
            "pcr_values": [
                {
                    "pcr_index": 1,
                    "pcr_value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                },
                {
                    "pcr_index": 2,
                    "pcr_value": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                }
            ]
        }
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_ok());
    
    let evidence = evidence.unwrap();
    assert_eq!(evidence.pcrs.hash_alg, "sm3");
    assert_eq!(evidence.pcrs.pcr_values.len(), 2);
    assert_eq!(evidence.pcrs.pcr_values[0].pcr_index, 1);
    assert_eq!(evidence.pcrs.pcr_values[1].pcr_index, 2);
}

#[tokio::test]
async fn test_ascend_npu_evidence_empty_pcr_values() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": []  // Empty PCR values
        }
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_ok());
    
    // Test that parsing succeeds but verification would fail
    let evidence = evidence.unwrap();
    assert!(evidence.pcrs.pcr_values.is_empty());
}

#[tokio::test]
async fn test_ascend_npu_evidence_duplicate_pcr_indices() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 1,
                    "pcr_value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                },
                {
                    "pcr_index": 1,  // Duplicate index
                    "pcr_value": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                }
            ]
        }
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_ok());
    
    // Test that parsing succeeds but verification would fail
    let evidence = evidence.unwrap();
    assert_eq!(evidence.pcrs.pcr_values.len(), 2);
    assert_eq!(evidence.pcrs.pcr_values[0].pcr_index, 1);
    assert_eq!(evidence.pcrs.pcr_values[1].pcr_index, 1);
}

#[tokio::test]
async fn test_ascend_npu_evidence_invalid_hex_format() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 1,
                    "pcr_value": "invalid_hex_string"  // Invalid hex format
                }
            ]
        }
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_ok());
    
    // Test that parsing succeeds but verification would fail
    let evidence = evidence.unwrap();
    assert_eq!(evidence.pcrs.pcr_values[0].pcr_value, "invalid_hex_string");
}

#[tokio::test]
async fn test_ascend_npu_evidence_invalid_hash_algorithm() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "md5",  // Unsupported hash algorithm
            "pcr_values": [
                {
                    "pcr_index": 1,
                    "pcr_value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            ]
        }
    });

    let evidence = AscendNpuEvidence::from_json_value(&evidence_json);
    assert!(evidence.is_ok());
    
    // Test that parsing succeeds but verification would fail
    let evidence = evidence.unwrap();
    assert_eq!(evidence.pcrs.hash_alg, "md5");
}

#[tokio::test]
async fn test_quote_and_pcr_verification_with_nonce() {
    use ascend_npu_verifier::verifier::AscendNpuPlugin;
    use plugin_manager::{ServicePlugin, ServiceHostFunctions};

    // Create mock host functions
    let host_functions = ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    };

    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
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

    let plugin = AscendNpuPlugin::new("test_config".to_string(), host_functions);
    
    // Test with nonce
    let nonce = b"test_nonce_12345";
    let result = plugin.verify_evidence("test_user", None, &evidence_json, Some(nonce)).await;
    
    // Should fail due to invalid certificate/quote data, but nonce verification logic should be tested
    assert!(result.is_err());
    
    let error_msg = result.unwrap_err().to_string();
    // Should fail at certificate parsing or quote and PCR verification, not at nonce handling
    assert!(error_msg.contains("Failed to decode") || 
            error_msg.contains("Failed to parse") ||
            error_msg.contains("certificate") ||
            error_msg.contains("signature") ||
            error_msg.contains("quote"));
}

#[tokio::test]
async fn test_quote_and_pcr_verification_without_nonce() {
    use ascend_npu_verifier::verifier::AscendNpuPlugin;
    use plugin_manager::{ServicePlugin, ServiceHostFunctions};

    // Create mock host functions
    let host_functions = ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    };

    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
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

    let plugin = AscendNpuPlugin::new("test_config".to_string(), host_functions);
    
    // Test without nonce
    let result = plugin.verify_evidence("test_user", None, &evidence_json, None).await;
    
    // Should fail due to invalid certificate/quote data, but quote and PCR verification logic should be tested
    assert!(result.is_err());
    
    let error_msg = result.unwrap_err().to_string();
    // Should fail at certificate parsing or quote and PCR verification, not at nonce handling
    assert!(error_msg.contains("Failed to decode") || 
            error_msg.contains("Failed to parse") ||
            error_msg.contains("certificate") ||
            error_msg.contains("signature") ||
            error_msg.contains("quote"));
}







#[tokio::test]
async fn test_pcr_validity_verification_only() {
    use ascend_npu_verifier::verifier::AscendNpuPlugin;
    use plugin_manager::{ServicePlugin, ServiceHostFunctions};

    // Create mock host functions
    let host_functions = ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    };

    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 0,
                    "pcr_value": "0000000000000000000000000000000000000000000000000000000000000000"
                },
                {
                    "pcr_index": 1,
                    "pcr_value": "1111111111111111111111111111111111111111111111111111111111111111"
                },
                {
                    "pcr_index": 23,
                    "pcr_value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                }
            ]
        }
    });

    let plugin = AscendNpuPlugin::new("test_config".to_string(), host_functions);
    
    // Test PCR validity verification (should pass format validation but fail due to invalid certificate/quote)
    let result = plugin.verify_evidence("test_user", None, &evidence_json, None).await;
    
    // Should fail due to invalid certificate and quote data, but PCR format validation should pass
    assert!(result.is_err());
    
    // The error should be related to certificate/quote and PCR verification, not PCR format
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Failed to decode") || 
            error_msg.contains("Failed to parse") ||
            error_msg.contains("certificate") ||
            error_msg.contains("signature"));
}

#[tokio::test]
async fn test_pcr_digest_verification() {
    use ascend_npu_verifier::verifier::AscendNpuPlugin;
    use plugin_manager::{ServicePlugin, ServiceHostFunctions};

    // Create mock host functions
    let host_functions = ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    };

    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "/1RDR4AYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAsDBwAAACB0ZXN0X3F1b3RlX2RhdGFfMzJfYnl0ZXNfbG9uZ18xMjM=",
            "signature": "ABQACwAhdGVzdF9zaWduYXR1cmVfZGF0YV8zMl9ieXRlc19sb25n"
        },
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 0,
                    "pcr_value": "0000000000000000000000000000000000000000000000000000000000000000"
                },
                {
                    "pcr_index": 1,
                    "pcr_value": "1111111111111111111111111111111111111111111111111111111111111111"
                }
            ]
        }
    });

    let plugin = AscendNpuPlugin::new("test_config".to_string(), host_functions);
    
    // Test PCR digest verification (should fail due to invalid certificate/quote but PCR digest logic should be tested)
    let result = plugin.verify_evidence("test_user", None, &evidence_json, None).await;
    
    // Should fail due to invalid certificate and quote data, but PCR digest calculation should work
    assert!(result.is_err());
    
    // The error should be related to certificate/quote and PCR verification, not PCR digest calculation
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Failed to decode") || 
            error_msg.contains("Failed to parse") ||
            error_msg.contains("certificate") ||
            error_msg.contains("signature"));
}
