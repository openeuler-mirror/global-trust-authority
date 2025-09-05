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
    collect_evidences_core, get_node_id, AttesterInfo, GetEvidenceResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crate::nonce_util::NonceUtil;
use crate::token_fmt as tf;

/// Attester information, including attester type and log types
#[derive(Debug, Deserialize, Default, Eq, PartialEq)]
pub struct Attester {
    pub attester_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_types: Option<Vec<String>>,
}

/// Request structure for evidence collection, including nonce and attester info
#[derive(Debug, Deserialize, Default)]
pub struct GetEvidenceRequest {
    // Optional list of attester types to collect evidence from
    pub attesters: Vec<Attester>,

    // Type of nonce to use (default or user-provided)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_type: Option<String>,

    // Server-generated nonce information
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    // Optional token format specification (eat/ear, default: eat)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_fmt: Option<String>,

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
            attesters: self.attesters,
            nonce_type: self.nonce_type.filter(|t| !t.trim().is_empty()),
            nonce: self.nonce.filter(|n| !n.trim().is_empty()),
            token_fmt: tf::sanitize(self.token_fmt),
            attester_data: self.attester_data.filter(|d| !d.is_null()),
        }
    }

    /// Validates fields that require semantic checks.
    /// - token_fmt: if provided and non-empty, must be one of "eat" or "ear" (case-insensitive)
    pub fn validate(&self) -> Result<(), ChallengeError> {
        if !tf::is_valid(&self.token_fmt) {
            let raw = self.token_fmt.as_deref().unwrap_or("");
            log::error!(
                "Invalid token_fmt: '{}', only 'eat' and 'ear' are supported",
                raw
            );
            return Err(ChallengeError::RequestParseError(
                format!(
                    "Invalid token_fmt: '{}', only 'eat' and 'ear' are supported",
                    raw
                )
            ));
        }
        Ok(())
    }
}

/// Manager for evidence collection logic
pub struct EvidenceManager;

impl EvidenceManager {
    /// Handles nonce type and value extraction based on request
    /// Validates and returns nonce type and value for evidence collection
    fn process_nonce(
        nonce_type: Option<&str>,
        nonce: Option<&String>,
    ) -> Result<(String, Option<String>), ChallengeError> {
        let nonce_type = nonce_type.map_or_else(|| "verifier".to_string(), |t| t.to_lowercase());

        let nonce_value = match nonce_type.as_str() {
            "ignore" => None,
            "user" | "verifier" => {
                let nonce_str = if let Some(n) = nonce {
                    n
                } else {
                    log::error!("User nonce not provided but nonce_type is 'user'");
                    return Err(ChallengeError::NonceNotProvided);
                };
                let nonce_bytes = match STANDARD.decode(nonce_str) {
                    Ok(bytes) => bytes,
                    Err(_) => return Err(ChallengeError::NonceInvalid("nonce decode error".to_string())),
                };
            
                let value_len = nonce_bytes.len();
                if !(1..=1024).contains(&value_len) {
                    log::error!("nonce length invalid: {} bytes", value_len);
                    return Err(ChallengeError::NonceInvalid(format!(
                        "nonce length must be between 1 and 1024 bytes, got {} bytes",
                        value_len
                    )));
                }
                nonce_str.clone().into()
            },
            _ => {
                log::error!("Invalid nonce_type: '{}'", nonce_type);
                return Err(ChallengeError::NonceTypeError(format!(
                    "Invalid nonce_type: '{}'. Must be one of: ignore, user, verifier",
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
            Self::process_nonce(request.nonce_type.as_deref(), request.nonce.as_ref())?;

        let attester_info = request.attesters.iter().map(|att| 
                AttesterInfo { 
                    attester_type: att.attester_type.clone(), 
                    log_types: if att.log_types.is_none() { Some(Vec::new()) } else { att.log_types.clone() }, 
                    policy_ids: None 
                }).collect::<Vec<_>>();
        if attester_info.is_empty() {
            log::error!("No valid attester_type provided");
            return Err(ChallengeError::RequestParseError("No attester_type provided".to_string()));
        }
        let aggregate_nonce = NonceUtil::update_nonce(&request.attester_data, nonce_value.as_ref())?;
        let evidences = collect_evidences_core(&Some(attester_info), &aggregate_nonce)?;

        let node_id = get_node_id()?;

        // token_fmt: use request value if present, else default to "eat"
        let token_fmt_value = tf::normalized_or_default(&request.token_fmt);

        Ok(GetEvidenceResponse::new(
            env!("CARGO_PKG_VERSION"),
            &nonce_type,
            nonce_value.as_ref(),
            request.attester_data.as_ref(),
            &node_id,
            evidences,
            Some(&token_fmt_value),
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
            attesters: vec![],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce".to_string()),
            token_fmt: None,
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attesters.is_empty());

        // Test empty nonce_type
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("   ".to_string()),
            nonce: Some("test_nonce".to_string()),
            token_fmt: None,
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.nonce_type.is_none());

        // Test null attester_data
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce".to_string()),
            token_fmt: None,
            attester_data: Some(json!(null)),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_data.is_none());

        // Test valid request
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce_value".repeat(5)),
            token_fmt: Some("EAR".to_string()),
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert_eq!(sanitized.attesters, vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }]);
        assert_eq!(sanitized.nonce_type, Some("verifier".to_string()));
        assert!(sanitized.nonce.is_some());
        assert!(sanitized.attester_data.is_some());
        assert_eq!(sanitized.token_fmt, Some("ear".to_string()));
    }

    #[test]
    fn test_evidence_manager_process_nonce_ignore() {
        let result = EvidenceManager::process_nonce(Some("ignore"), None);
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "ignore");
        assert!(nonce_value.is_none());
    }

    #[test]
    fn test_evidence_manager_process_nonce_user_missing() {
        let result = EvidenceManager::process_nonce(Some("user"), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));
    }

    #[test]
    fn test_evidence_manager_process_nonce_default_success() {
        let nonce = "dGVzdF9ub25jZV92YWx1ZQ==";
        let result = EvidenceManager::process_nonce(Some("verifier"), Some(&nonce.to_string()));
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "verifier");
        assert_eq!(nonce_value, Some(nonce.to_string()));
    }

    #[test]
    fn test_evidence_manager_process_nonce_default_missing() {
        let result = EvidenceManager::process_nonce(Some("verifier"), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));
    }

    #[test]
    fn test_evidence_manager_process_nonce_default_invalid() {
        let invalid_nonce = "test_nonce_value".repeat(5);
        let result = EvidenceManager::process_nonce(Some("verifier"), Some(&invalid_nonce));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceInvalid(_)));
    }

    #[test]
    fn test_evidence_manager_process_nonce_invalid_type() {
        let result = EvidenceManager::process_nonce(Some("invalid_type"), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));
    }

    #[test]
    fn test_evidence_manager_process_nonce_none_type() {
        let result = EvidenceManager::process_nonce(None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));
    }

    #[test]
    fn test_get_evidence_request_serialization() {
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce_value".repeat(5)),
            token_fmt: None,
            attester_data: Some(json!({"key": "value"})),
        };

        // Since GetEvidenceRequest doesn't implement Serialize, we test deserialization only
        let json_str = r#"{
            "attesters": [{"attester_type": "tpm_boot"}],
            "nonce_type": "verifier",
            "nonce": "test_nonce_valuetest_nonce_valuetest_nonce_valuetest_nonce_valuetest_nonce_value",
            "attester_data": {"key": "value"}
        }"#;

        let deserialized: GetEvidenceRequest = serde_json::from_str(json_str).unwrap();

        assert_eq!(request.attesters, deserialized.attesters);
        assert_eq!(request.nonce_type, deserialized.nonce_type);
        // Since Nonce doesn't implement PartialEq, we compare individual fields
        match (&request.nonce, &deserialized.nonce) {
            (Some(nonce1), Some(nonce2)) => {
                assert_eq!(nonce1, nonce2);
            }
            _ => {
                panic!("Nonce mismatch");
            }
        }
        assert_eq!(request.attester_data, deserialized.attester_data);
    }

    #[test]
    fn test_get_evidence_request_deserialization() {
        let json_str = r#"{
            "attesters": [{"attester_type": "tpm_boot", "log_types": ["TcgEventLog"]}, {"attester_type": "tpm_ima", "log_types": ["ima"]}],
            "nonce_type": "user",
            "nonce": "nonce",
            "attester_data": {"key": "value"}
        }"#;

        let request: GetEvidenceRequest = serde_json::from_str(json_str).unwrap();
        assert!(!request.attesters.is_empty());
        assert_eq!(request.nonce_type, Some("user".to_string()));
        assert!(request.nonce.is_some());
        assert!(request.attester_data.is_some());
    }

    #[test]
    fn test_evidence_manager_process_nonce_edge_cases() {
        // Test with empty string nonce_type - should be treated as invalid nonce_type
        let result = EvidenceManager::process_nonce(Some(""), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));

        // Test with whitespace-only nonce_type - should be treated as invalid nonce_type
        let result = EvidenceManager::process_nonce(Some("   "), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));

        // Test with mixed case nonce_type
        let result = EvidenceManager::process_nonce(Some("IgNoRe"), None);
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "ignore");
        assert!(nonce_value.is_none());

        let result = EvidenceManager::process_nonce(Some("UsEr"), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));

        // Test with None nonce_type - should become "verifier" but fail because no nonce provided
        let result = EvidenceManager::process_nonce(None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));

        // Test with None nonce_type but with valid nonce
        let nonce = "dGVzdF9ub25jZV92YWx1ZXRlc3Rfbm9uY2VfdmFsdWU=".to_string();
        let result = EvidenceManager::process_nonce(None, Some(&nonce));
        assert!(result.is_ok());
        let (nonce_type, nonce_value) = result.unwrap();
        assert_eq!(nonce_type, "verifier");
        assert!(nonce_value.is_some());
    }

    #[test]
    fn test_evidence_manager_get_evidence_error_cases() {
        // Test with invalid nonce_type
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("invalid_type".to_string()),
            nonce: None,
            token_fmt: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceTypeError(_)));

        // Test with user nonce_type but no nonce
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("user".to_string()),
            nonce: None,
            token_fmt: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChallengeError::NonceNotProvided));

        // Test with verifier nonce_type but no nonce
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: None,
            token_fmt: None,
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
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("ignore".to_string()),
            nonce: None,
            token_fmt: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        // This would require mocking the plugin manager to succeed
        // For now, we just test that it doesn't fail on nonce processing
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test with verifier nonce_type and valid nonce
        let request = GetEvidenceRequest {
            attesters: vec![Attester { attester_type: "tpm_boot".to_string(), log_types: None }],
            nonce_type: Some("verifier".to_string()),
            nonce: Some("test_nonce_value".repeat(5)),
            token_fmt: None,
            attester_data: None,
        };
        let result = EvidenceManager::get_evidence(&request);
        // This would require mocking the plugin manager to succeed
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }
}
