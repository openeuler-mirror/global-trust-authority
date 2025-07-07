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

use crate::challenge::{do_challenge, get_cached_token_for_current_node, AttesterInfo};
use crate::challenge_error::TokenError;
use serde::{Deserialize, Serialize};

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
}

impl TokenRequest {
    /// Sanitizes the request by removing empty values for robust processing
    /// Sanitizes the request by removing empty values:
    /// - Converts empty `attester_info` vector to None
    /// - Keeps challenge flag as is (Option<bool> is already well-handled)
    /// - Converts empty or whitespace-only `attester_data` to None
    pub fn sanitize(self) -> Self {
        TokenRequest {
            attester_info: self.attester_info.and_then(|info| if info.is_empty() { None } else { Some(info) }),
            challenge: self.challenge,
            attester_data: self.attester_data.and_then(|data| if data.is_null() { None } else { Some(data) }),
        }
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
        if !token_request.challenge.unwrap_or(false) {
            if let Some(token) = get_cached_token_for_current_node() {
                return Ok(token);
            }
        }

        match do_challenge(&token_request.attester_info, &token_request.attester_data).await {
            Ok(token) => Ok(token),
            Err(e) => {
                log::error!("Challenge failed, {}", e);
                Err(TokenError::challenge_error(e.to_string()))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_token_request_sanitize() {
        // Test empty attester_info
        let request = TokenRequest {
            attester_info: Some(vec![]),
            challenge: Some(false),
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());

        // Test null attester_data
        let request = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: None,
            }]),
            challenge: Some(true),
            attester_data: Some(json!(null)),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_data.is_none());

        // Test valid request
        let request = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: Some(vec!["policy1".to_string()]),
            }]),
            challenge: Some(false),
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_some());
        assert_eq!(sanitized.challenge, Some(false));
        assert!(sanitized.attester_data.is_some());

        // Test None values
        let request = TokenRequest {
            attester_info: None,
            challenge: None,
            attester_data: None,
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());
        assert!(sanitized.challenge.is_none());
        assert!(sanitized.attester_data.is_none());
    }

    #[test]
    fn test_token_request_serialization() {
        let request = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"test": "data"})),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: TokenRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request.attester_info, deserialized.attester_info);
        assert_eq!(request.challenge, deserialized.challenge);
        assert_eq!(request.attester_data, deserialized.attester_data);
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
            "attester_data": {"test": "data"}
        }"#;

        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_some());
        assert_eq!(request.challenge, Some(true));
        assert!(request.attester_data.is_some());
    }

    #[test]
    fn test_token_request_default() {
        let request = TokenRequest::default();
        assert!(request.attester_info.is_none());
        assert!(request.challenge.is_none());
        assert!(request.attester_data.is_none());
    }

    #[test]
    fn test_attester_info_serialization() {
        let attester_info = AttesterInfo {
            attester_type: Some("tpm_boot".to_string()),
            policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);
    }

    #[test]
    fn test_attester_info_partial_eq() {
        let info1 = AttesterInfo {
            attester_type: Some("tpm_boot".to_string()),
            policy_ids: Some(vec!["policy1".to_string()]),
        };

        let info2 = AttesterInfo {
            attester_type: Some("tpm_boot".to_string()),
            policy_ids: Some(vec!["policy1".to_string()]),
        };

        let info3 = AttesterInfo {
            attester_type: Some("tpm_ima".to_string()),
            policy_ids: Some(vec!["policy1".to_string()]),
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
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());
        assert!(sanitized.challenge.is_none());
        assert!(sanitized.attester_data.is_none());

        // Test with empty attester_info
        let request = TokenRequest {
            attester_info: Some(vec![]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_none());
        assert_eq!(sanitized.challenge, Some(true));
        assert!(sanitized.attester_data.is_some());

        // Test with null attester_data
        let request = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: None,
            }]),
            challenge: Some(false),
            attester_data: Some(json!(null)),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_some());
        assert_eq!(sanitized.challenge, Some(false));
        assert!(sanitized.attester_data.is_none());

        // Test with very large attester_info
        let large_attester_info = vec![
            AttesterInfo {
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
            },
            AttesterInfo {
                attester_type: Some("tpm_ima".to_string()),
                policy_ids: Some(vec!["policy3".to_string(), "policy4".to_string()]),
            },
        ];
        let request = TokenRequest {
            attester_info: Some(large_attester_info.clone()),
            challenge: Some(true),
            attester_data: Some(json!({"complex": {"nested": "data"}})),
        };
        let sanitized = request.sanitize();
        assert!(sanitized.attester_info.is_some());
        assert_eq!(sanitized.attester_info.unwrap(), large_attester_info);
        assert_eq!(sanitized.challenge, Some(true));
        assert!(sanitized.attester_data.is_some());
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
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: Some(vec!["policy1".to_string(), "policy2".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(complex_data.clone()),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: TokenRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request.attester_info, deserialized.attester_info);
        assert_eq!(request.challenge, deserialized.challenge);
        assert_eq!(request.attester_data, deserialized.attester_data);
    }

    #[test]
    fn test_token_request_deserialization_edge_cases() {
        // Test with minimal JSON
        let json_str = r#"{}"#;
        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_none());
        assert!(request.challenge.is_none());
        assert!(request.attester_data.is_none());

        // Test with partial JSON
        let json_str = r#"{"challenge": true}"#;
        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_none());
        assert_eq!(request.challenge, Some(true));
        assert!(request.attester_data.is_none());

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
            "attester_data": {"test": "data"}
        }"#;

        let request: TokenRequest = serde_json::from_str(json_str).unwrap();
        assert!(request.attester_info.is_some());
        assert_eq!(request.challenge, Some(false));
        assert!(request.attester_data.is_some());

        let attester_info = request.attester_info.unwrap();
        assert_eq!(attester_info.len(), 2);
        assert_eq!(attester_info[0].attester_type, Some("tpm_boot".to_string()));
        assert_eq!(attester_info[0].policy_ids, Some(vec!["policy1".to_string(), "policy2".to_string()]));
        assert_eq!(attester_info[1].attester_type, Some("tpm_ima".to_string()));
        assert!(attester_info[1].policy_ids.is_none());
    }

    #[test]
    fn test_token_manager_get_token_error_cases() {
        // Test with challenge=true but no attester_info
        let request = TokenRequest {
            attester_info: None,
            challenge: Some(true),
            attester_data: None,
        };
        let result = futures::executor::block_on(TokenManager::get_token(&request));
        // This would require mocking do_challenge to succeed
        assert!(result.is_err()); // Expected to fail due to missing plugin manager

        // Test with challenge=false but no cached token
        let request = TokenRequest {
            attester_info: None,
            challenge: Some(false),
            attester_data: None,
        };
        let result = futures::executor::block_on(TokenManager::get_token(&request));
        // This would require mocking get_cached_token_for_current_node to return None
        // and then do_challenge to succeed
        assert!(result.is_err()); // Expected to fail due to missing plugin manager
    }

    #[test]
    fn test_token_request_comparison() {
        let request1 = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: Some(vec!["policy1".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
        };

        let request2 = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: Some("tpm_boot".to_string()),
                policy_ids: Some(vec!["policy1".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
        };

        let request3 = TokenRequest {
            attester_info: Some(vec![AttesterInfo {
                attester_type: Some("tpm_ima".to_string()),
                policy_ids: Some(vec!["policy1".to_string()]),
            }]),
            challenge: Some(true),
            attester_data: Some(json!({"key": "value"})),
        };

        // Since TokenRequest doesn't implement PartialEq, we compare individual fields
        assert_eq!(request1.attester_info.as_ref().unwrap().len(), request2.attester_info.as_ref().unwrap().len());
        assert_eq!(request1.challenge, request2.challenge);
        assert_eq!(request1.attester_data, request2.attester_data);

        // Test that they are different from request3
        assert_ne!(request1.attester_info.as_ref().unwrap()[0].attester_type, request3.attester_info.as_ref().unwrap()[0].attester_type);
    }

    #[test]
    fn test_attester_info_edge_cases() {
        // Test with None values
        let attester_info = AttesterInfo {
            attester_type: None,
            policy_ids: None,
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);

        // Test with empty strings and vectors
        let attester_info = AttesterInfo {
            attester_type: Some("".to_string()),
            policy_ids: Some(vec![]),
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);

        // Test with special characters
        let special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
        let attester_info = AttesterInfo {
            attester_type: Some(special_chars.to_string()),
            policy_ids: Some(vec![special_chars.to_string()]),
        };

        let serialized = serde_json::to_string(&attester_info).unwrap();
        let deserialized: AttesterInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(attester_info.attester_type, deserialized.attester_type);
        assert_eq!(attester_info.policy_ids, deserialized.policy_ids);
    }
}
