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

use challenge::{
    challenge_error::{ChallengeError, TokenError},
    challenge::{AttesterInfo, GetEvidenceResponse, EvidenceWithPolicy, Measurement},
    evidence::{Attester, GetEvidenceRequest, EvidenceManager},
    token::TokenRequest,
};
use serde_json::json;
use base64::Engine;

#[test]
fn test_full_evidence_collection_flow() {
    let request = GetEvidenceRequest {
        attesters: vec![Attester {
            attester_type: "tpm_boot".to_string(),
            log_types: Some(vec!["TcgEventLog".to_string()]),
        }],
        nonce_type: Some("verifier".to_string()),
        nonce: Some("test_nonce_value".repeat(5)),
        attester_data: Some(json!({"test": "data"})),
        token_fmt: None,
    };

    let sanitized = request.sanitize();
    assert_eq!(sanitized.attesters, vec![Attester {
        attester_type: "tpm_boot".to_string(),
        log_types: Some(vec!["TcgEventLog".to_string()]),
    }]);
    assert_eq!(sanitized.nonce_type, Some("verifier".to_string()));

    let result = EvidenceManager::get_evidence(&sanitized);
    assert!(result.is_err()); // Expected to fail due to missing plugin manager
}

#[test]
fn test_token_request_flow() {
    let request = TokenRequest {
        attester_info: Some(vec![AttesterInfo {
            attester_type: "tpm_boot".to_string(),
            policy_ids: Some(vec!["policy1".to_string()]),
            log_types: Some(vec!["TcgEventLog".to_string()]),
        }]),
        challenge: Some(false),
        attester_data: Some(json!({"test": "data"})),
        token_fmt: None,
    };

    let sanitized = request.sanitize();
    assert!(sanitized.attester_info.is_some());
    assert_eq!(sanitized.challenge, Some(false));
    assert!(sanitized.attester_data.is_some());
}

#[test]
fn test_error_handling_integration() {
    let request = GetEvidenceRequest {
        attesters: vec![Attester {
            attester_type: "tpm_boot".to_string(),
            log_types: Some(vec!["TcgEventLog".to_string()]),
        }],
        nonce_type: Some("user".to_string()),
        nonce: None,
        attester_data: None,
        token_fmt: None,
    };
    let result = EvidenceManager::get_evidence(&request);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));

    let request = GetEvidenceRequest {
        attesters: vec![Attester {
            attester_type: "tpm_boot".to_string(),
            log_types: Some(vec!["TcgEventLog".to_string()]),
        }],
        nonce_type: Some("invalid_type".to_string()),
        nonce: None,
        attester_data: None,
        token_fmt: None,
    };
    let result = EvidenceManager::get_evidence(&request);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));
}

#[test]
fn test_serialization_integration() {
    let attester_info = AttesterInfo {
        attester_type: "tpm_boot".to_string(),
        policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
        log_types: Some(vec!["TcgEventLog".to_string()]),
    };

    let serialized = serde_json::to_string(&attester_info).unwrap();
    let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

    assert_eq!(attester_info.attester_type, deserialized.attester_type);
    assert_eq!(attester_info.policy_ids, deserialized.policy_ids);

    let evidence = EvidenceWithPolicy {
        attester_type: "tpm_boot".to_string(),
        evidence: json!({"test": "evidence"}),
        policy_ids: Some(vec!["policy1".to_string()]),
    };

    let response = GetEvidenceResponse::new(
        "1.0.0",
        "verifier",
        None,
        None,
        "test_node",
        vec![evidence],
        None,
    );

    let serialized = serde_json::to_string(&response).unwrap();
    assert!(serialized.contains("1.0.0"));
    assert!(serialized.contains("verifier"));
    assert!(serialized.contains("test_node"));
    assert!(serialized.contains("tpm_boot"));
}

#[test]
fn test_request_sanitization_integration() {
    let empty_request = GetEvidenceRequest {
        attesters: vec![],
        nonce_type: Some("   ".to_string()),
        nonce: None,
        attester_data: Some(json!(null)),
        token_fmt: None,
    };

    let sanitized = empty_request.sanitize();
    assert!(sanitized.attesters.is_empty());
    assert!(sanitized.nonce_type.is_none());
    assert!(sanitized.attester_data.is_none());

    let empty_token_request = TokenRequest {
        attester_info: Some(vec![]),
        challenge: Some(true),
        attester_data: Some(json!(null)),
        token_fmt: None,
    };

    let sanitized = empty_token_request.sanitize();
    assert!(sanitized.attester_info.is_none());
    assert_eq!(sanitized.challenge, Some(true));
    assert!(sanitized.attester_data.is_none());
}

#[test]
fn test_measurement_construction() {
    let evidence1 = EvidenceWithPolicy {
        attester_type: "tpm_boot".to_string(),
        evidence: json!({"boot_evidence": "data"}),
        policy_ids: Some(vec!["boot_policy".to_string()]),
    };
    let evidence2 = EvidenceWithPolicy {
        attester_type: "tpm_ima".to_string(),
        evidence: json!({"ima_evidence": "data"}),
        policy_ids: None,
    };

    let evidences = vec![
        EvidenceWithPolicy {
            attester_type: evidence1.attester_type.clone(),
            evidence: evidence1.evidence.clone(),
            policy_ids: evidence1.policy_ids.clone(),
        },
        EvidenceWithPolicy {
            attester_type: evidence2.attester_type.clone(),
            evidence: evidence2.evidence.clone(),
            policy_ids: evidence2.policy_ids.clone(),
        },
    ];

    let measurement = Measurement {
        node_id: "test-node".to_string(),
        nonce_type: "ignore".to_string(),
        nonce: Some("test_nonce_value".repeat(5)),
        attester_data: Some(json!({"attester_data": "test"})),
        token_fmt: None,
        evidences, // move evidences
    };

    assert_eq!(measurement.node_id, "test-node");
    if let Some(measurement_nonce) = &measurement.nonce {
        assert_eq!(measurement_nonce, &"test_nonce_value".repeat(5));
    } else {
        panic!("Expected nonce to be Some");
    }
    assert_eq!(measurement.evidences.len(), 2);
    assert_eq!(measurement.evidences[0].attester_type, "tpm_boot");
    assert_eq!(measurement.evidences[1].attester_type, "tpm_ima");

    let serialized = serde_json::to_string(&measurement).unwrap();
    assert!(serialized.contains("test-node"));
    assert!(serialized.contains("tpm_boot"));
    assert!(serialized.contains("tpm_ima"));
}

#[test]
fn test_evidence_response_construction() {
    let evidence1 = EvidenceWithPolicy {
        attester_type: "tpm_boot".to_string(),
        evidence: json!({"boot_evidence": "data"}),
        policy_ids: Some(vec!["boot_policy".to_string()]),
    };
    let evidence2 = EvidenceWithPolicy {
        attester_type: "tpm_ima".to_string(),
        evidence: json!({"ima_evidence": "data"}),
        policy_ids: None,
    };
    let evidences = vec![
        EvidenceWithPolicy {
            attester_type: evidence1.attester_type.clone(),
            evidence: evidence1.evidence.clone(),
            policy_ids: evidence1.policy_ids.clone(),
        },
        EvidenceWithPolicy {
            attester_type: evidence2.attester_type.clone(),
            evidence: evidence2.evidence.clone(),
            policy_ids: evidence2.policy_ids.clone(),
        },
    ];

    let response = GetEvidenceResponse::new(
        "2.0.0",
        "ignore",
        None,
        None,
        "test_node_id",
        evidences, // move evidences
        None,
    );

    assert_eq!(response.agent_version, "2.0.0");
    assert_eq!(response.measurements.len(), 1);
    assert_eq!(response.measurements[0].node_id, "test_node_id");
    assert_eq!(response.measurements[0].evidences.len(), 2);
    assert_eq!(response.measurements[0].evidences[0].attester_type, "tpm_boot");
    assert_eq!(response.measurements[0].evidences[1].attester_type, "tpm_ima");
}

#[test]
fn test_error_handling_comprehensive() {
    // Test all ChallengeError variants
    let errors = vec![
        ChallengeError::ConfigError("config error".to_string()),
        ChallengeError::PluginNotFound("plugin not found".to_string()),
        ChallengeError::EvidenceCollectionFailed("evidence failed".to_string()),
        ChallengeError::NoValidEvidence("no evidence".to_string()),
        ChallengeError::NonceTypeError("invalid type".to_string()),
        ChallengeError::NonceValueEmpty,
        ChallengeError::NonceNotProvided,
        ChallengeError::NonceInvalid("invalid nonce".to_string()),
        ChallengeError::TokenNotReceived,
        ChallengeError::RequestParseError("parse error".to_string()),
        ChallengeError::NetworkError("network error".to_string()),
        ChallengeError::ServerError("server error".to_string()),
        ChallengeError::InternalError("internal error".to_string()),
        ChallengeError::TokenError(TokenError::ChallengeError("token error".to_string())),
    ];

    for error in errors {
        let error_string = error.to_string();
        assert!(!error_string.is_empty());
        assert!(error_string.len() > 0);
    }
}

#[test]
fn test_measurement_edge_cases() {
    // Test with multiple evidences
    let evidences = vec![
        EvidenceWithPolicy {
            attester_type: "tpm_boot".to_string(),
            evidence: json!({"boot": "evidence1"}),
            policy_ids: Some(vec!["policy1".to_string()]),
        },
        EvidenceWithPolicy {
            attester_type: "tpm_ima".to_string(),
            evidence: json!({"ima": "evidence2"}),
            policy_ids: Some(vec!["policy2".to_string(), "policy3".to_string()]),
        },
        EvidenceWithPolicy {
            attester_type: "custom_attester".to_string(),
            evidence: json!({"custom": "evidence3"}),
            policy_ids: None,
        },
    ];

    let measurement = Measurement {
        node_id: "test-node".to_string(),
        nonce_type: "ignore".to_string(),
        nonce: None,
        attester_data: None,
        token_fmt: None,
        evidences, // move evidences
    };

    assert_eq!(measurement.evidences.len(), 3);
    assert_eq!(measurement.evidences[0].attester_type, "tpm_boot");
    assert_eq!(measurement.evidences[1].attester_type, "tpm_ima");
    assert_eq!(measurement.evidences[2].attester_type, "custom_attester");

    let serialized = serde_json::to_string(&measurement).unwrap();
    assert!(serialized.contains("tpm_boot"));
    assert!(serialized.contains("tpm_ima"));
    assert!(serialized.contains("custom_attester"));
    assert!(serialized.contains("policy1"));
    assert!(serialized.contains("policy2"));
    assert!(serialized.contains("policy3"));
}

#[test]
fn test_get_evidence_response_edge_cases() {
    // Test with multiple measurements
    let evidences1 = vec![EvidenceWithPolicy {
        attester_type: "tpm_boot".to_string(),
        evidence: json!({"boot": "evidence"}),
        policy_ids: None,
    }];

    let evidences2 = vec![EvidenceWithPolicy {
        attester_type: "tpm_ima".to_string(),
        evidence: json!({"ima": "evidence"}),
        policy_ids: None,
    }];

    let response = GetEvidenceResponse {
        agent_version: "2.0.0".to_string(),
        measurements: vec![
            Measurement {
                node_id: "node1".to_string(),
                nonce_type: "ignore".to_string(),
                nonce: None,
                attester_data: None,
                token_fmt: None,
                evidences: evidences1,
            },
            Measurement {
                node_id: "node2".to_string(),
                nonce_type: "ignore".to_string(),
                nonce: None,
                attester_data: None,
                token_fmt: None,
                evidences: evidences2,
            },
        ],
    };

    assert_eq!(response.measurements.len(), 2);
    assert_eq!(response.measurements[0].node_id, "node1");
    assert_eq!(response.measurements[1].node_id, "node2");

    let serialized = serde_json::to_string(&response).unwrap();
    assert!(serialized.contains("node1"));
    assert!(serialized.contains("node2"));
    assert!(serialized.contains("tpm_boot"));
    assert!(serialized.contains("tpm_ima"));
}

#[test]
fn test_base64_edge_cases() {
    // Test with binary data
    let binary_data = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&binary_data);
    let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
    assert_eq!(binary_data, decoded);

    // Test with unicode characters
    let unicode_string = "Hello, 世界! 🌍";
    let encoded = base64::engine::general_purpose::STANDARD.encode(unicode_string.as_bytes());
    let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
    let decoded_string = String::from_utf8(decoded).unwrap();
    assert_eq!(unicode_string, decoded_string);

    // Test with very long string
    let long_string = "a".repeat(10000);
    let encoded = base64::engine::general_purpose::STANDARD.encode(long_string.as_bytes());
    let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
    let decoded_string = String::from_utf8(decoded).unwrap();
    assert_eq!(long_string, decoded_string);
}

#[test]
fn test_json_serialization_edge_cases() {
    // Test with nested JSON structures
    let complex_json = json!({
        "nested": {
            "array": [1, 2, 3, "string", null, true, false],
            "object": {
                "key1": "value1",
                "key2": 42,
                "key3": null,
                "key4": true
            }
        },
        "simple": "value"
    });

    let evidence = EvidenceWithPolicy {
        attester_type: "complex_attester".to_string(),
        evidence: complex_json.clone(),
        policy_ids: None,
    };

    let serialized = serde_json::to_string(&evidence).unwrap();
    assert!(serialized.contains("complex_attester"));
    assert!(serialized.contains("nested"));
    assert!(serialized.contains("array"));
    assert!(serialized.contains("object"));
}

    #[test]
    fn test_evidence_token_fmt_sanitize_validate() {
        // empty string should sanitize to None and validate OK
        let req = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce_value".repeat(5)),
            token_fmt: Some("".to_string()),
            attester_data: None,
        };
        let sanitized = req.sanitize();
        assert_eq!(sanitized.token_fmt.as_deref(), Some(""));
        assert!(sanitized.validate().is_err());

        // valid 'EAR' mixed case should become lowercase and pass
        let req = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce_value".repeat(5)),
            token_fmt: Some("EAR".to_string()),
            attester_data: None,
        };
        let sanitized = req.sanitize();
        assert_eq!(sanitized.token_fmt.as_deref(), Some("ear"));
        assert!(sanitized.validate().is_ok());

        // invalid value should error in validate
        let req = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce_value".repeat(5)),
            token_fmt: Some("invalid".to_string()),
            attester_data: None,
        };
        let sanitized = req.sanitize();
        assert!(sanitized.token_fmt.as_deref().is_some());
        assert!(sanitized.validate().is_err());
    }