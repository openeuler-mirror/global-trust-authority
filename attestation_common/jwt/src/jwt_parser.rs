use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use openssl::hash::MessageDigest;
use crate::jwt_error::JwtError;

pub struct JwtParser {}

impl JwtParser {
    pub fn get_alg(content: &str) -> Result<MessageDigest, JwtError> {
        let data_vec: Vec<&str> = content.split('.').collect();
        let header_str = BASE64_URL_SAFE_NO_PAD
            .decode(data_vec[0])
            .map_err(|_| JwtError::IncorrectFormatError("Failed to decode JWT header".to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|_| JwtError::IncorrectFormatError("JWT header is not valid UTF-8".to_string()))
            })?;
        if header_str.contains("S384") {
            Ok(MessageDigest::sha384())
        } else if header_str.contains("S512") {
            Ok(MessageDigest::sha512())
        } else if header_str.contains("SM3") {
            Ok(MessageDigest::sm3())
        } else {
            Err(JwtError::IncorrectFormatError(format!("unsupported algorithm: {}", header_str)))
        }
    }

    pub fn get_signature(content: &str) -> Result<Vec<u8>, JwtError> {
        let data_vec: Vec<&str> = content.split('.').collect();
        BASE64_URL_SAFE_NO_PAD
            .decode(data_vec[2])
            .map_err(|e| JwtError::IncorrectFormatError(e.to_string()))
    }
    
    pub fn get_payload(content: &str) -> Result<String, JwtError> {
        let data_vec: Vec<&str> = content.split('.').collect();
        BASE64_URL_SAFE_NO_PAD
            .decode(data_vec[1])
            .map_err(|_| JwtError::IncorrectFormatError("Failed to decode JWT payload".to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|_| JwtError::IncorrectFormatError("JWT payload is not valid UTF-8".to_string()))
            })
    }

    pub fn get_base_data(content: &str) -> String {
        let data_vec: Vec<&str> = content.split('.').collect();
        format!("{}.{}", data_vec[0], data_vec[1])
    }
}