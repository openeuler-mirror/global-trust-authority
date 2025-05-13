use crate::challenge_error::TokenError;
use crate::challenge::{AttesterInfo, do_challenge, get_cached_token_for_current_node};
use serde::{Serialize, Deserialize};

/// Request structure for token acquisition, including attester info and challenge flag
#[derive(Debug, Serialize, Deserialize)]
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
    pub attester_data: Option<String>,
}

impl TokenRequest {
    /// Sanitizes the request by removing empty values for robust processing
    /// Sanitizes the request by removing empty values:
    /// - Converts empty attester_info vector to None
    /// - Keeps challenge flag as is (Option<bool> is already well-handled)
    /// - Converts empty or whitespace-only attester_data to None
    pub fn sanitize(self) -> Self {
        TokenRequest {
            attester_info: self.attester_info.and_then(|info| if info.is_empty() { None } else { Some(info) }),
            challenge: self.challenge,
            attester_data: self.attester_data.and_then(|data| if data.trim().is_empty() { None } else { Some(data) }),
        }
    }

    /// Creates a default instance with all fields set to None
    pub fn default() -> Self {
        Self {
            attester_info: None,
            challenge: None,
            attester_data: None,
        }
    }
}

/// Manager for token acquisition logic
pub struct TokenManager;

impl TokenManager {
    /// Main function to get a token, using cache if possible or performing a challenge if needed
    pub async fn get_token(token_request: &TokenRequest) -> Result<serde_json::Value, TokenError> {
        if !token_request.challenge.unwrap_or(false) {
            if let Some(token) = get_cached_token_for_current_node() {
                return Ok(token);
            }
        }

        match do_challenge(&token_request.attester_info, &token_request.attester_data).await {
            Ok(token) => Ok(token),
            Err(e) => {
                log::error!("Challenge failed, {}", e.to_string());
                Err(TokenError::challenge_error(e.to_string()))
            },
        }
    }
}

