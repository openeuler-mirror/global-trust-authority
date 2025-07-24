use openssl::sha::Sha256;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json;
use crate::challenge_error::ChallengeError;

/// Nonce utility for updating nonce based on attester data and nonce
pub struct NonceUtil;

impl NonceUtil {
    /// Update nonce based on attester data and nonce
    /// 
    /// # Arguments
    /// * `attester_data` - Optional attester data to include in the nonce
    /// * `nonce` - Optional nonce to include in the nonce
    /// 
    /// # Returns
    /// * `Option<String>` - Updated nonce as a base64 string, or None if both inputs are None
    pub fn update_nonce(attester_data: &Option<serde_json::Value>, nonce: Option<&String>) -> Result<Option<String>, ChallengeError> {
        // If both inputs are None, return None
        if attester_data.is_none() && nonce.is_none() {
            return Ok(None);
        }

        // Create a new SHA-256 hasher
        let mut hasher = Sha256::new();

        // Update with nonce if it exists
        if let Some(nonce_str) = nonce {
            let base64_nonce = STANDARD.decode(nonce_str).map_err(|_| ChallengeError::NonceInvalid("Nonce is not base64 encoded.".to_string()))?;
            hasher.update(&base64_nonce);
        }

        // Update with attester_data if it exists
        if let Some(data) = attester_data {
            // Convert to string and then to bytes
            let data_str = data.to_string();
            // Base64 encode the string
            let base64_data = STANDARD.encode(&data_str);
            hasher.update(base64_data.as_bytes());
        }

        // Finalize the hash
        let hash_result = hasher.finish();
        // Convert hash to base64
        let result = STANDARD.encode(hash_result);

        Ok(Some(result))
    }    
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_update_nonce() {
        let nonce = Some(STANDARD.encode("nonce_value"));
        let attester_data = Some(serde_json::json!({"key": "value"}));
        let updated_nonce = NonceUtil::update_nonce(&attester_data, nonce.as_ref());
        assert!(updated_nonce.is_ok());
    }

    #[test]
    fn test_update_nonce_with_none() {
        let nonce = Some("".to_string());
        let attester_data = None;
        let updated_nonce = NonceUtil::update_nonce(&attester_data, nonce.as_ref());
        assert!(updated_nonce.is_ok());
    }

    #[test]
    fn test_different_input_nonce() {
        let nonce1 = Some(STANDARD.encode("nonce_value1"));
        let nonce2 = Some(STANDARD.encode("nonce_value2"));
        let attester_data = Some(serde_json::json!({"key": "value"}));
        let nonce1 = NonceUtil::update_nonce(&attester_data, nonce1.as_ref()).unwrap().unwrap();
        let nonce2 = NonceUtil::update_nonce(&attester_data, nonce2.as_ref()).unwrap().unwrap();
        assert_ne!(nonce1, nonce2);
    }

    
    #[test]
    fn test_different_attester_data() {
        let nonce = Some(STANDARD.encode("nonce_value"));
        let attester_data1 = Some(serde_json::json!({"key1": "value1"}));
        let attester_data2 = Some(serde_json::json!({"key2": "value2"}));
        let nonce1 = NonceUtil::update_nonce(&attester_data1, nonce.as_ref()).unwrap().unwrap();
        let nonce2 = NonceUtil::update_nonce(&attester_data2, nonce.as_ref()).unwrap().unwrap();
        assert_ne!(nonce1, nonce2);
    }
}
