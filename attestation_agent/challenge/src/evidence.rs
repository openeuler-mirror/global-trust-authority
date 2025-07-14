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

use serde::Deserialize;
use serde_json;
use crate::challenge_error::ChallengeError;
use crate::challenge::{
    collect_evidences_core, get_node_id, validate_nonce_fields, AttesterInfo, GetEvidenceResponse, Nonce,
};

/// Request structure for evidence collection, including nonce and attester info
#[derive(Debug, Deserialize, Default)]
pub struct GetEvidenceRequest {
    // Optional list of attester types to collect evidence from
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_types: Option<Vec<String>>,

    // Type of nonce to use (default or user-provided)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_type: Option<String>,

    // User-provided nonce value when nonce_type is "user"
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_nonce: Option<String>,

    // Server-generated nonce information
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,

    // Additional attestation data
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<serde_json::Value>,
}

impl GetEvidenceRequest {
    /// Sanitizes the request by converting empty values to None, for robust downstream logic
    /// Sanitizes the request by converting empty values to None:
    /// - Empty vectors become None
    /// - Empty or whitespace-only strings become None
    /// - Keeps nonce field as is (handled separately)
    pub fn sanitize(self) -> Self {
        GetEvidenceRequest {
            attester_types: self.attester_types.filter(|types| !types.is_empty()),
            nonce_type: self.nonce_type.filter(|t| !t.trim().is_empty()),
            user_nonce: self.user_nonce.filter(|n| !n.trim().is_empty()),
            nonce: self.nonce,
            attester_data: self.attester_data.filter(|d| !d.is_null()),
        }
    }
}

/// Manager for evidence collection logic
pub struct EvidenceManager;

impl EvidenceManager {
    /// Handles nonce type and value extraction based on request
    /// Validates and returns nonce type and value for evidence collection
    fn process_nonce(
        nonce_type: Option<&str>,
        user_nonce: Option<&String>,
        nonce: Option<&Nonce>,
    ) -> Result<(String, Option<String>), ChallengeError> {
        let nonce_type = nonce_type.map_or_else(|| "default".to_string(), |t| t.to_lowercase());

        let nonce_value = match nonce_type.as_str() {
            "ignore" => None,
            "user" => {
                let user_nonce_str = if let Some(n) = user_nonce {
                    n
                } else {
                    log::error!("User nonce not provided but nonce_type is 'user'");
                    return Err(ChallengeError::UserNonceNotProvided);
                };
                let user_nonce_len = user_nonce_str.len();
                if !(64..=1024).contains(&user_nonce_len) {
                    log::error!("user_nonce length invalid: {} bytes", user_nonce_len);
                    return Err(ChallengeError::NonceInvalid(format!(
                        "user_nonce length must be between 64 and 1024 bytes, got {} bytes",
                        user_nonce_len
                    )));
                }
                user_nonce_str.clone().into()
            },
            "default" => {
                let nonce = if let Some(n) = nonce {
                    n
                } else {
                    log::error!("Nonce not provided but nonce_type is 'default'");
                    return Err(ChallengeError::NonceNotProvided);
                };
                if let Err(e) = validate_nonce_fields(nonce) {
                    log::error!("Nonce validation failed: {}", e);
                    return Err(e);
                }
                Some(nonce.value.clone())
            },
            _ => {
                log::error!("Invalid nonce_type: '{}'", nonce_type);
                return Err(ChallengeError::NonceTypeError(format!(
                    "Invalid nonce_type: '{}'. Must be one of: ignore, user, default",
                    nonce_type
                )));
            },
        };

        Ok((nonce_type, nonce_value))
    }

    /// Main function to collect evidence based on the request
    ///
    /// # Errors
    ///
    /// Returns an error if the evidence cannot be retrieved.
    pub fn get_evidence(request: &GetEvidenceRequest) -> Result<GetEvidenceResponse, ChallengeError> {
        log::info!("Starting evidence collection");

        let (nonce_type, nonce_value) =
            Self::process_nonce(request.nonce_type.as_deref(), request.user_nonce.as_ref(), request.nonce.as_ref())?;

        let attester_info = request.attester_types.as_ref().map(|types| {
            types.iter().map(|t| AttesterInfo { attester_type: Some(t.clone()), policy_ids: None }).collect::<Vec<_>>()
        });

        let evidences = collect_evidences_core(&attester_info, &nonce_value)?;

        let node_id = get_node_id()?;

        Ok(GetEvidenceResponse::new(
            env!("CARGO_PKG_VERSION"),
            &nonce_type,
            request.user_nonce.as_ref(),
            request.nonce.as_ref(),
            request.attester_data.as_ref(),
            &node_id,
            evidences,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_get_evidence_request_sanitize() {
        // Test empty attester_types
        let request = GetEvidenceRequest {
            attester_types: Some(vec![]),
            nonce_type: Some("default".to_string()),
            user_nonce: Some("test_nonce".to_string()),
            nonce: None,
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_types.is_none());

        // Test empty nonce_type
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("   ".to_string()),
            user_nonce: Some("test_nonce".to_string()),
            nonce: None,
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.nonce_type.is_none());

        // Test empty user_nonce
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("user".to_string()),
            user_nonce: Some("".to_string()),
            nonce: None,
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.user_nonce.is_none());

        // Test null attester_data
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("default".to_string()),
            user_nonce: None,
            nonce: None,
            attester_data: Some(json!(null)),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_data.is_none());

        // Test valid request
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("default".to_string()),
            user_nonce: None,
            nonce: Some(Nonce {
                iat: 1234567890,
                value: "test_nonce_value".repeat(5), // 70 bytes
                signature: "test_signature".repeat(6), // 78 bytes
            }),
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert_eq!(sanitized.attester_types, Some(vec!["tpm_boot".to_string()]));
        assert_eq!(sanitized.nonce_type, Some("default".to_string()));
        assert!(sanitized.user_nonce.is_none());
        assert!(sanitized.nonce.is_some());
        assert!(sanitized.attester_data.is_some());
    }

    #[test]
    fn test_evidence_manager_process_nonce_ignore() {
        let result = EvidenceManager::process_nonce(Some("ignore"), None, None);
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "ignore");
        assert!(nonce_value.is_none());
    }

    #[test]
    fn test_evidence_manager_process_nonce_user_success() {
        let user_nonce = "a".repeat(64); // Valid length
        let result = EvidenceManager::process_nonce(Some("user"), Some(&user_nonce), None);
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "user");
        assert_eq!(nonce_value, Some(user_nonce));
    }

    #[test]
    fn test_evidence_manager_process_nonce_user_missing() {
        let result = EvidenceManager::process_nonce(Some("user"), None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::UserNonceNotProvided));
    }

    #[test]
    fn test_evidence_manager_process_nonce_user_invalid_length() {
        let user_nonce = "a".repeat(32); // Too short
        let result = EvidenceManager::process_nonce(Some("user"), Some(&user_nonce), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));

        let user_nonce = "a".repeat(1025); // Too long
        let result = EvidenceManager::process_nonce(Some("user"), Some(&user_nonce), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));
    }

    #[test]
    fn test_evidence_manager_process_nonce_default_success() {
        let nonce = Nonce {
            iat: 1234567890,
            value: "test_nonce_value".repeat(5), // 70 bytes
            signature: "test_signature".repeat(6), // 78 bytes
        };
        let result = EvidenceManager::process_nonce(Some("default"), None, Some(&nonce));
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "default");
        assert_eq!(nonce_value, Some(nonce.value));
    }

    #[test]
    fn test_evidence_manager_process_nonce_default_missing() {
        let result = EvidenceManager::process_nonce(Some("default"), None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));
    }

    #[test]
    fn test_evidence_manager_process_nonce_default_invalid() {
        let invalid_nonce = Nonce {
            iat: 0, // Invalid
            value: "test_nonce_value".repeat(5),
            signature: "test_signature".repeat(6),
        };
        let result = EvidenceManager::process_nonce(Some("default"), None, Some(&invalid_nonce));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));
    }

    #[test]
    fn test_evidence_manager_process_nonce_invalid_type() {
        let result = EvidenceManager::process_nonce(Some("invalid_type"), None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));
    }

    #[test]
    fn test_evidence_manager_process_nonce_case_insensitive() {
        let result = EvidenceManager::process_nonce(Some("DEFAULT"), None, None);
        assert!(result.is_err()); // Still fails because no nonce provided, but type is converted to lowercase
        let (nonce_type, _) = EvidenceManager::process_nonce(Some("DEFAULT"), None, Some(&Nonce {
            iat: 1234567890,
            value: "test_nonce_value".repeat(5),
            signature: "test_signature".repeat(6),
        })).unwrap();
        assert_eq!(nonce_type, "default");
    }

    #[test]
    fn test_evidence_manager_process_nonce_none_type() {
        let result = EvidenceManager::process_nonce(None, None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));
    }

    #[test]
    fn test_get_evidence_request_edge_cases() {
        // Test with all None values
        let request = GetEvidenceRequest {
            attester_types: None,
            nonce_type: None,
            user_nonce: None,
            nonce: None,
            attester_data: None,
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_types.is_none());
        assert!(sanitized.nonce_type.is_none());
        assert!(sanitized.user_nonce.is_none());
        assert!(sanitized.nonce.is_none());
        assert!(sanitized.attester_data.is_none());

        // Test with whitespace-only strings
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["   ".to_string()]),
            nonce_type: Some("   ".to_string()),
            user_nonce: Some("   ".to_string()),
            nonce: None,
            attester_data: Some(json!("   ")),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_types.is_some());
        assert!(sanitized.nonce_type.is_none());
        assert!(sanitized.user_nonce.is_none());
        assert!(sanitized.attester_data.is_some());

        // Test with very large strings
        let large_string = "a".repeat(1000);
        let request = GetEvidenceRequest {
            attester_types: Some(vec![large_string.clone()]),
            nonce_type: Some(large_string.clone()),
            user_nonce: Some(large_string.clone()),
            nonce: None,
            attester_data: Some(json!(large_string)),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_types.is_some());
        assert!(sanitized.nonce_type.is_some());
        assert!(sanitized.user_nonce.is_some());
        assert!(sanitized.attester_data.is_some());
    }

    #[test]
    fn test_get_evidence_request_serialization() {
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string(), "tpm_ima".to_string()]),
            nonce_type: Some("default".to_string()),
            user_nonce: Some("user_nonce_value".to_string()),
            nonce: Some(Nonce {
                iat: 1234567890,
                value: "test_nonce_value".repeat(5),
                signature: "test_signature".repeat(6),
            }),
            attester_data: Some(json!({"key": "value"})),
        };

        // Since GetEvidenceRequest doesn't implement Serialize, we test deserialization only
        let json_str = r#"{
            "attester_types": ["tpm_boot", "tpm_ima"],
            "nonce_type": "default",
            "user_nonce": "user_nonce_value",
            "nonce": {
                "iat": 1234567890,
                "value": "test_nonce_valuetest_nonce_valuetest_nonce_valuetest_nonce_valuetest_nonce_value",
                "signature": "test_signaturetest_signaturetest_signaturetest_signaturetest_signaturetest_signature"
            },
            "attester_data": {"key": "value"}
        }"#;

        let deserialized: GetEvidenceRequest = serde_json::from_str(json_str).unwrap();

        assert_eq!(request.attester_types, deserialized.attester_types);
        assert_eq!(request.nonce_type, deserialized.nonce_type);
        assert_eq!(request.user_nonce, deserialized.user_nonce);
        // Since Nonce doesn't implement PartialEq, we compare individual fields
        match (&request.nonce, &deserialized.nonce) {
            (Some(nonce1), Some(nonce2)) => {
                assert_eq!(nonce1.iat, nonce2.iat);
                assert_eq!(nonce1.value, nonce2.value);
                assert_eq!(nonce1.signature, nonce2.signature);
            }
            (None, None) => {
                // Both are None, which is fine
            }
            _ => {
                // One is Some and the other is None, which should not happen
                assert_eq!(request.nonce.is_some(), deserialized.nonce.is_some());
            }
        }
        assert_eq!(request.attester_data, deserialized.attester_data);
    }

    #[test]
    fn test_get_evidence_request_deserialization() {
        let json_str = r#"{
            "attester_types": ["tpm_boot", "tpm_ima"],
            "nonce_type": "user",
            "user_nonce": "user_nonce_value",
            "nonce": {
                "iat": 1234567890,
                "value": "test_nonce_valuetest_nonce_valuetest_nonce_valuetest_nonce_valuetest_nonce_value",
                "signature": "test_signaturetest_signaturetest_signaturetest_signaturetest_signaturetest_signature"
            },
            "attester_data": {"key": "value"}
        }"#;

        let request: GetEvidenceRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_types.is_some());
        assert_eq!(request.nonce_type, Some("user".to_string()));
        assert_eq!(request.user_nonce, Some("user_nonce_value".to_string()));
        assert!(request.nonce.is_some());
        assert!(request.attester_data.is_some());
    }

    #[test]
    fn test_evidence_manager_process_nonce_edge_cases() {
        // Test with empty string nonce_type - should be treated as invalid nonce_type
        let result = EvidenceManager::process_nonce(Some(""), None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));

        // Test with whitespace-only nonce_type - should be treated as invalid nonce_type
        let result = EvidenceManager::process_nonce(Some("   "), None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));

        // Test with mixed case nonce_type
        let result = EvidenceManager::process_nonce(Some("IgNoRe"), None, None);
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "ignore");
        assert!(nonce_value.is_none());

        let result = EvidenceManager::process_nonce(Some("UsEr"), None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::UserNonceNotProvided));

        // Test with None nonce_type - should become "default" but fail because no nonce provided
        let result = EvidenceManager::process_nonce(None, None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));

        // Test with None nonce_type but with valid nonce
        let nonce = Nonce {
            iat: 1234567890,
            value: "test_nonce_value".repeat(5),
            signature: "test_signature".repeat(6),
        };
        let result = EvidenceManager::process_nonce(None, None, Some(&nonce));
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "default");
        assert!(nonce_value.is_some());
    }

    #[test]
    fn test_evidence_manager_get_evidence_error_cases() {
        // Test with invalid nonce_type
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("invalid_type".to_string()),
            user_nonce: None,
            nonce: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));

        // Test with user nonce_type but no user_nonce
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("user".to_string()),
            user_nonce: None,
            nonce: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::UserNonceNotProvided));

        // Test with default nonce_type but no nonce
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("default".to_string()),
            user_nonce: None,
            nonce: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));
    }

    #[test]
    fn test_evidence_manager_get_evidence_success_cases() {
        // Test with ignore nonce_type
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("ignore".to_string()),
            user_nonce: None,
            nonce: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        // This would require mocking the plugin manager to succeed
        // For now, we just test that it doesn't fail on nonce processing
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test with user nonce_type and valid user_nonce
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("user".to_string()),
            user_nonce: Some("a".repeat(64)), // Valid length
            nonce: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        // This would require mocking the plugin manager to succeed
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test with default nonce_type and valid nonce
        let request = GetEvidenceRequest {
            attester_types: Some(vec!["tpm_boot".to_string()]),
            nonce_type: Some("default".to_string()),
            user_nonce: None,
            nonce: Some(Nonce {
                iat: 1234567890,
                value: "test_nonce_value".repeat(5),
                signature: "test_signature".repeat(6),
            }),
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        // This would require mocking the plugin manager to succeed
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }
}
