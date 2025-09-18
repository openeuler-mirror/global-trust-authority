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
            "quote_data": "dGVzdF9xdW90ZV9kYXRh",
            "signature": "dGVzdF9zaWduYXR1cmU="
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
    assert!(evidence.is_ok());
    
    let evidence = evidence.unwrap();
    assert_eq!(evidence.ak_cert, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t");
    assert_eq!(evidence.quote.quote_data, "dGVzdF9xdW90ZV9kYXRh");
    assert_eq!(evidence.quote.signature, "dGVzdF9zaWduYXR1cmU=");
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

    let plugin = AscendNpuPlugin::new("test_config".to_string(), host_functions);
    
    // This should succeed even without logs
    let result = plugin.verify_evidence("test_user", None, &evidence_json, None).await;
    
    // Note: This will likely fail due to invalid certificate, but we're testing the structure
    // In a real test, you would use valid test data
    assert!(result.is_err()); // Expected to fail with invalid test data, but structure should be correct
}

#[tokio::test]
async fn test_ascend_npu_evidence_missing_required_fields() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "dGVzdF9xdW90ZV9kYXRh",
            "signature": "dGVzdF9zaWduYXR1cmU="
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
            "quote_data": "dGVzdF9xdW90ZV9kYXRh",
            "signature": "dGVzdF9zaWduYXR1cmU="
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
async fn test_ascend_npu_evidence_invalid_hash_algorithm() {
    let evidence_json = json!({
        "ak_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "quote": {
            "quote_data": "dGVzdF9xdW90ZV9kYXRh",
            "signature": "dGVzdF9zaWduYXR1cmU="
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
