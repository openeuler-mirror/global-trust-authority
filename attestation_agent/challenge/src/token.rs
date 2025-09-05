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

use crate::challenge::{do_challenge, get_cached_token_for_current_node_with_fmt, AttesterInfo};
use crate::challenge_error::TokenError;
use serde::{Deserialize, Serialize};
use crate::token_fmt as tf;

/// Request structure for token acquisition, including attester info and challenge flag
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TokenRequest {
    // Optional vector of attester information for the token request
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_info: Option<Vec<AttesterInfo>>,

    // Optional flag to force a new challenge request
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<bool>,

    // Optional additional data for attestation
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<serde_json::Value>,

    // Optional token format specification (eat/ear, default: eat)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_fmt: Option<String>,
}

impl TokenRequest {
    /// Sanitizes the request by removing empty values for robust processing
    /// Sanitizes the request by removing empty values:
    /// - Converts empty `attester_info` vector to None
    /// - Keeps challenge flag as is (Option<bool> is already well-handled)
    /// - Converts empty or whitespace-only `attester_data` to None
    /// - Normalizes token_fmt to lowercase if provided
    /// - Converts empty token_fmt string to None (will use default "eat")
    pub fn sanitize(self) -> Self {
        TokenRequest {
            attester_info: self.attester_info.and_then(|info| if info.is_empty() { None } else { Some(info) }),
            challenge: self.challenge,
            attester_data: self.attester_data.and_then(|data| if data.is_null() { None } else { Some(data) }),
            token_fmt: tf::sanitize(self.token_fmt),
        }
    }

    /// Validates fields that require semantic checks.
    /// - token_fmt: if provided and non-empty, must be one of "eat" or "ear" (case-insensitive)
    pub fn validate(&self) -> Result<(), TokenError> {
        if !tf::is_valid(&self.token_fmt) {
            let raw = self.token_fmt.as_deref().unwrap_or("");
            log::error!(
                "Invalid token_fmt: '{}', only 'eat' and 'ear' are supported",
                raw
            );
            return Err(TokenError::invalid_token_format(
                format!(
                    "Invalid token_fmt: '{}', only 'eat' and 'ear' are supported",
                    raw
                )
            ));
        }
        Ok(())
    }
}

/// Manager for token acquisition logic
pub struct TokenManager;

impl TokenManager {
    /// Main function to get a token, using cache if possible or performing a challenge if needed
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be retrieved.
    pub async fn get_token(token_request: &TokenRequest) -> Result<serde_json::Value, TokenError> {
        // Get normalized token format, defaulting to "eat" if not specified or empty
        let token_fmt = tf::normalized_or_default(&token_request.token_fmt);

        // Try to get cached token if challenge is not forced
        if !token_request.challenge.unwrap_or(false) {
            match get_cached_token_for_current_node_with_fmt(token_fmt.as_str()) {
                Ok(Some(token)) => return Ok(token),
                Ok(None) => {
                    log::info!("No cached token for requested format, proceeding to challenge");
                },
                Err(e) => {
                    log::warn!("Cache lookup failed ({}), proceeding to challenge", e);
                },
            }
        }

        // Perform challenge to get new token
        do_challenge(&token_request.attester_info, &token_request.attester_data, Some(token_fmt.as_str()))
            .await
            .map_err(|e| {
                log::error!("Challenge failed, {}", e);
                TokenError::challenge_error(e.to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper function to create a basic TokenRequest for testing
    fn create_test_request(
        attester_info: Option<Vec<AttesterInfo>>,
        challenge: Option<bool>,
        attester_data: Option<serde_json::Value>,
        token_fmt: Option<String>,
    ) -> TokenRequest {
        TokenRequest {
            attester_info,
            challenge,
            attester_data,
            token_fmt,
        }
    }

    /// Helper function to create a basic AttesterInfo for testing
    fn create_test_attester_info(
        attester_type: &str,
        policy_ids: Option<Vec<String>>,
        log_types: Option<Vec<String>>,
    ) -> AttesterInfo {
        AttesterInfo {
            attester_type: attester_type.to_string(),
            policy_ids,
            log_types,
        }
    }

    #[test]
    fn test_token_request_sanitize() {
        // Test empty attester_info
        let request = create_test_request(
            Some(vec![]),
            Some(false),
            Some(json!({"key": "value"})),
            Some("ear".to_string()),
        );
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());
        assert_eq!(sanitized.token_fmt, Some("ear".to_string()));

        // Test null attester_data
        let request = create_test_request(
            Some(vec![create_test_attester_info("tpm_boot", None, Some(vec!["TcgEventLog".to_string()]))]),
            Some(true),
            Some(json!(null)),
            Some("eat".to_string()),
        );
        let sanitized = request.sanitize();
        assert!(sanitized.attester_data.is_none());
        assert_eq!(sanitized.token_fmt, Some("eat".to_string()));

        // Test valid request
        let request = create_test_request(
            Some(vec![create_test_attester_info(
                "tpm_boot",
                Some(vec!["policy1".to_string()]),
                Some(vec!["TcgEventLog".to_string()]),
            )]),
            Some(false),
            Some(json!({"key": "value"})),
            Some("ear".to_string()),
        );
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_some());
        assert_eq!(sanitized.challenge, Some(false));
        assert!(sanitized.attester_data.is_some());
        assert_eq!(sanitized.token_fmt, Some("ear".to_string()));

        // Test None values
        let request = create_test_request(None, None, None, None);
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());
        assert!(sanitized.challenge.is_none());
        assert!(sanitized.attester_data.is_none());
        assert!(sanitized.token_fmt.is_none());
    }

    #[test]
    fn test_token_request_serialization() {
        let request = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
                log_types: Some(vec!["TcgEventLog".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"test": "data"})),
            token_fmt: Some("ear".to_string()),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: TokenRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request.attester_info, deserialized.attester_info);
        assert_eq!(request.challenge, deserialized.challenge);
        assert_eq!(request.attester_data, deserialized.attester_data);
        assert_eq!(request.token_fmt, deserialized.token_fmt);
    }

    #[test]
    fn test_token_request_deserialization() {
        let json_str = r#"{
            "attester_info": [
                {
                    "attester_type": "tpm_boot",
                    "policy_ids": ["policy1", "policy2"]
                }
            ],
            "challenge": true,
            "attester_data": {"test": "data"},
            "token_fmt": "ear"
        }"#;

        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_some());
        assert_eq!(request.challenge, Some(true));
        assert!(request.attester_data.is_some());
        assert_eq!(request.token_fmt, Some("ear".to_string()));
    }

    #[test]
    fn test_token_request_default() {
        let request = TokenRequest::default();
        assert!(request.attester_info.is_none());
        assert!(request.challenge.is_none());
        assert!(request.attester_data.is_none());
        assert!(request.token_fmt.is_none());
    }

    #[test]
    fn test_attester_info_serialization() {
        let attester_info = AttesterInfo {
            attester_type: "tpm_boot".to_string(),
            policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
            log_types: Some(vec!["TcgEventLog".to_string()]),
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);
    }

    #[test]
    fn test_attester_info_partial_eq() {
        let info1 = AttesterInfo {
            attester_type: "tpm_boot".to_string(),
            policy_ids: Some(vec!["policy1".to_string()]),
            log_types: Some(vec!["TcgEventLog".to_string()]),
        };

        let info2 = AttesterInfo {
            attester_type: "tpm_boot".to_string(),
            policy_ids: Some(vec!["policy1".to_string()]),
            log_types: Some(vec!["TcgEventLog".to_string()]),
        };

        let info3 = AttesterInfo {
            attester_type: "tpm_ima".to_string(),
            policy_ids: Some(vec!["policy1".to_string()]),
            log_types: Some(vec!["ImaLog".to_string()]),
        };

        assert_eq!(info1, info2);
        assert_ne!(info1, info3);
    }

    #[test]
    fn test_token_request_edge_cases() {
        // Test with all None values
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: None,
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());
        assert!(sanitized.challenge.is_none());
        assert!(sanitized.attester_data.is_none());
        assert!(sanitized.token_fmt.is_none());

        // Test with empty attester_info
        let request = TokenRequest {
            attester_info: Some(vec![]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
            token_fmt: Some("ear".to_string()),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());
        assert_eq!(sanitized.challenge, Some(true));
        assert!(sanitized.attester_data.is_some());
        assert_eq!(sanitized.token_fmt, Some("ear".to_string()));

        // Test with null attester_data
        let request = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: None,
                log_types: None,
            }]),
            challenge: Some(false),
            attester_data: Some(json!(null)),
            token_fmt: Some("eat".to_string()),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_some());
        assert_eq!(sanitized.challenge, Some(false));
        assert!(sanitized.attester_data.is_none());
        assert_eq!(sanitized.token_fmt, Some("eat".to_string()));

        // Test with very large attester_info
        let large_attester_info = vec![
            AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
                log_types: Some(vec!["TcgEventLog".to_string()]),
            },
            AttesterInfo {
                attester_type: "tpm_ima".to_string(),
                policy_ids: Some(vec!["policy3".to_string(), "policy4".to_string()]),
                log_types: Some(vec!["ImaLog".to_string()]),
            },
        ];
        let request = TokenRequest {
            attester_info: Some(large_attester_info.clone()),
            challenge: Some(true),
            attester_data: Some(json!({"complex": {"nested": "data"}})),
            token_fmt: Some("ear".to_string()),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_some());
        assert_eq!(sanitized.attester_info.unwrap(), large_attester_info);
        assert_eq!(sanitized.challenge, Some(true));
        assert!(sanitized.attester_data.is_some());
        assert_eq!(sanitized.token_fmt, Some("ear".to_string()));
    }

    #[test]
    fn test_token_request_serialization_edge_cases() {
        // Test with complex JSON data
        let complex_data = json!({
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

        let request = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
                log_types: Some(vec!["TcgEventLog".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(complex_data.clone()),
            token_fmt: Some("ear".to_string()),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: TokenRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request.attester_info, deserialized.attester_info);
        assert_eq!(request.challenge, deserialized.challenge);
        assert_eq!(request.attester_data, deserialized.attester_data);
        assert_eq!(request.token_fmt, deserialized.token_fmt);
    }

    #[test]
    fn test_token_request_deserialization_edge_cases() {
        // Test with minimal JSON
        let json_str = r#"{}"#;
        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_none());
        assert!(request.challenge.is_none());
        assert!(request.attester_data.is_none());
        assert!(request.token_fmt.is_none());

        // Test with partial JSON
        let json_str = r#"{"challenge": true}"#;
        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_none());
        assert_eq!(request.challenge, Some(true));
        assert!(request.attester_data.is_none());
        assert!(request.token_fmt.is_none());

        // Test with complex attester_info
        let json_str = r#"{
            "attester_info": [
                {
                    "attester_type": "tpm_boot",
                    "policy_ids": ["policy1", "policy2"]
                },
                {
                    "attester_type": "tpm_ima",
                    "policy_ids": null
                }
            ],
            "challenge": false,
            "attester_data": {"test": "data"},
            "token_fmt": "ear"
        }"#;

        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_some());
        assert_eq!(request.challenge, Some(false));
        assert!(request.attester_data.is_some());
        assert_eq!(request.token_fmt, Some("ear".to_string()));

        let attester_info = request.attester_info.unwrap();
        assert_eq!(attester_info.len(), 2);
        assert_eq!(attester_info[0].attester_type, "tpm_boot".to_string());
        assert_eq!(attester_info[0].policy_ids, Some(vec!["policy1".to_string(), "policy2".to_string()]));
        assert_eq!(attester_info[1].attester_type, "tpm_ima".to_string());
        assert!(attester_info[1].policy_ids.is_none());
    }

    #[test]
    fn test_token_manager_get_token_error_cases() {
        // Test with challenge=true but no attester_info
        let request = TokenRequest {
            attester_info: None,
            challenge: Some(true),
            attester_data: None,
            token_fmt: Some("ear".to_string()),
        };
        let result = futures::executor::block_on(TokenManager::get_token(&request));
        // This would require mocking do_challenge to succeed
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test with challenge=false but no cached token
        let request = TokenRequest {
            attester_info: None,
            challenge: Some(false),
            attester_data: None,
            token_fmt: Some("ear".to_string()),
        };
        let result = futures::executor::block_on(TokenManager::get_token(&request));
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_token_request_comparison() {
        let request1 = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: Some(vec!["policy1".to_string()]),
                log_types: Some(vec!["TcgEventLog".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
            token_fmt: Some("ear".to_string()),
        };

        let request2 = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: "tpm_boot".to_string(),
                policy_ids: Some(vec!["policy1".to_string()]),
                log_types: Some(vec!["TcgEventLog".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
            token_fmt: Some("ear".to_string()),
        };

        let request3 = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: "tpm_ima".to_string(),
                policy_ids: Some(vec!["policy1".to_string()]),
                log_types: Some(vec!["ImaLog".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
            token_fmt: Some("ear".to_string()),
        };

        // Since TokenRequest doesn't implement PartialEq, we compare individual fields
        assert_eq!(request1.attester_info.as_ref().unwrap().len(), request2.attester_info.as_ref().unwrap().len());
        assert_eq!(request1.challenge, request2.challenge);
        assert_eq!(request1.attester_data, request2.attester_data);
        assert_eq!(request1.token_fmt, request2.token_fmt);

        // Test that they are different from request3
        assert_ne!(request1.attester_info.as_ref().unwrap()[0].attester_type, request3.attester_info.as_ref().unwrap()[0].attester_type);
    }

    #[test]
    fn test_attester_info_edge_cases() {
        // Test with None values
        let attester_info = AttesterInfo {
            attester_type: "tpm_boot".to_string(),
            policy_ids: None,
            log_types: None,
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);

        // Test with empty strings and vectors
        let attester_info = AttesterInfo {
            attester_type: ("".to_string()),
            policy_ids: Some(vec![]),
            log_types: None,
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);

        // Test with special characters
        let special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
        let attester_info = AttesterInfo {
            attester_type: special_chars.to_string(),
            policy_ids: Some(vec![special_chars.to_string()]),
            log_types: None,
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);
    }

    #[test]
    fn test_token_fmt_validation() {
        // Test valid token_fmt values
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("eat".to_string()),
        };
        let sanitized = request.sanitize();
        assert_eq!(sanitized.token_fmt, Some("eat".to_string()));

        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("ear".to_string()),
        };
        let sanitized = request.sanitize();
        assert_eq!(sanitized.token_fmt, Some("ear".to_string()));

        // Test case insensitive
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("EAT".to_string()),
        };
        let sanitized = request.sanitize();
        assert_eq!(sanitized.token_fmt, Some("eat".to_string()));

        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("EAR".to_string()),
        };
        let sanitized = request.sanitize();
        assert_eq!(sanitized.token_fmt, Some("ear".to_string()));

        // Test empty string token_fmt (should be converted to None)
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("".to_string()),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.token_fmt.is_none());

        // Test None token_fmt (should return None)
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: None,
        };
        let sanitized = request.sanitize();
        assert!(sanitized.token_fmt.is_none());
    }

    #[test]
    fn test_token_fmt_validation_errors() {
        // Test invalid token_fmt values
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("invalid".to_string()),
        };
        let sanitized = request.sanitize();
        let err = sanitized.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid token format"));

        // Test empty string token_fmt (should be converted to None, not error)
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("".to_string()),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.validate().is_ok());
        assert!(sanitized.token_fmt.is_none());

        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
            token_fmt: Some("EAT_TOKEN".to_string()),
        };
        let sanitized = request.sanitize();
        let err = sanitized.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid token format"));
    }
}
