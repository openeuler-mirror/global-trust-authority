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
pub mod register {
    use std::num::NonZero;
    use ring::digest::SHA256_OUTPUT_LEN;
    use ring::pbkdf2::PBKDF2_HMAC_SHA256;
    use ring::pbkdf2;
    use ring::rand::{SecureRandom, SystemRandom};
    use uuid::Uuid;
    use zeroize::Zeroize;
    use crate::error::register_error::RegisterError;
    
    pub static APIKEY_LENGTH: usize = 32; 
    pub static SALT_LENGTH: usize = 16;
    pub static PBKDF2_SIZE: u32 = 10000;

    pub struct ApiKeyInfo {
        pub uid: String,
        pub salt: Vec<u8>,
        pub apikey: String,
        pub hashed_key: Vec<u8>,
    }
   
    pub fn generate_apikey() -> Result<ApiKeyInfo, RegisterError> {
        let mut info = ApiKeyInfo {
            uid: "".to_string(),
            salt: vec![],
            apikey: "".to_string(),
            hashed_key: vec![0; SHA256_OUTPUT_LEN],
        };
        info.apikey = generate_str(APIKEY_LENGTH)?;
        info.salt = generate_random(SALT_LENGTH)?;
        // pbkdf2 hash计算
        let non_zero = match NonZero::new(PBKDF2_SIZE) {
            None => return Err(RegisterError::GenerateApiKeyError("".to_string())),
            Some(n) => {n}
        };
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            non_zero, 
            &info.salt,                      
            &info.apikey.as_bytes(),       
            &mut info.hashed_key                
        );
        info.uid = Uuid::new_v4().to_string();
        Ok(info)
    }
    
    pub fn refresh_apikey(apikey: &mut ApiKeyInfo) -> Result<(), RegisterError> {
        apikey.apikey = generate_str(APIKEY_LENGTH)?;
        let non_zero = match NonZero::new(PBKDF2_SIZE) {
            None => return Err(RegisterError::GenerateApiKeyError("".to_string())),
            Some(n) => {n}
        };
        apikey.hashed_key = vec![0; SHA256_OUTPUT_LEN];
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            non_zero,
            &apikey.salt,
            &apikey.apikey.as_bytes(),
            &mut apikey.hashed_key
        );
        Ok(())
    }

    pub fn get_hashed_key(apikey: &str, salt: &Vec<u8>) -> Result<Vec<u8>, RegisterError> {
        let non_zero = match NonZero::new(PBKDF2_SIZE) {
            None => return Err(RegisterError::GenerateApiKeyError("".to_string())),
            Some(n) => {n}
        };
        let mut hashed_key: Vec<u8> = vec![0; SHA256_OUTPUT_LEN];
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            non_zero,
            &salt,
            &apikey.as_bytes(),
            &mut hashed_key
        );
        Ok(hashed_key)
    }
    
    pub fn generate_str(size: usize) -> Result<String, RegisterError> {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rand = vec![0u8; size];
        SystemRandom::new().fill(&mut rand).map_err(|e| RegisterError::GenerateApiKeyError(format!("{}", e)))?;
        let mut key = String::with_capacity(size);
        let length = CHARSET.len() as u8;
        rand.iter().for_each(|&c| {
            key.push(CHARSET[(c % length) as usize] as char);
        });
        rand.zeroize();
        Ok(key)
    }

    pub fn generate_random(size: usize) -> Result<Vec<u8>, RegisterError> {
        let mut key = vec![0u8; size];
        SystemRandom::new().fill(&mut key).map_err(|e| RegisterError::GenerateApiKeyError(format!("{}", e)))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use ring::digest::SHA256_OUTPUT_LEN;
    use crate::apikey::register::{generate_apikey, generate_random, generate_str, get_hashed_key, refresh_apikey, APIKEY_LENGTH, SALT_LENGTH};

    #[test]
    fn test_generate_apikey() {
        let result = generate_apikey();
        assert!(result.is_ok());
        let api_key_info = result.unwrap();
        assert!(!api_key_info.uid.is_empty());
        assert_eq!(api_key_info.salt.len(), SALT_LENGTH);
        assert_eq!(api_key_info.apikey.len(), APIKEY_LENGTH);
        assert_eq!(api_key_info.hashed_key.len(), SHA256_OUTPUT_LEN);
        assert!(api_key_info.apikey.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_refresh_apikey() {
        let mut original = generate_apikey().unwrap();
        let old_apikey = original.apikey.clone();
        let old_hashed_key = original.hashed_key.clone();
        let result = refresh_apikey(&mut original);
        assert!(result.is_ok());
        assert_ne!(original.apikey, old_apikey);
        assert_ne!(original.hashed_key, old_hashed_key);
        assert!(!original.uid.is_empty());
        assert_eq!(original.salt.len(), SALT_LENGTH);
        assert_eq!(original.apikey.len(), APIKEY_LENGTH);
        assert_eq!(original.hashed_key.len(), SHA256_OUTPUT_LEN);
    }

    #[test]
    fn test_get_hashed_key() {
        let test_key = "test_api_key";
        let test_salt = generate_random(SALT_LENGTH);
        assert!(test_salt.is_ok());
        let test_salt = test_salt.unwrap();
        let result = get_hashed_key(test_key, &test_salt);
        assert!(result.is_ok());
        let hashed_key = result.unwrap();
        assert_eq!(hashed_key.len(), SHA256_OUTPUT_LEN);
        let result2 = get_hashed_key(test_key, &test_salt);
        assert_eq!(hashed_key, result2.unwrap());
        let different_salt = generate_random(SALT_LENGTH);
        assert!(different_salt.is_ok());
        let different_salt = different_salt.unwrap();
        let result3 = get_hashed_key(test_key, &different_salt);
        assert_ne!(hashed_key, result3.unwrap());
    }

    #[test]
    fn test_generate_str() {
        let test_size = 10;
        let result = generate_str(test_size);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), test_size);
        assert!(result.chars().all(|c| c.is_ascii_alphanumeric()));
        let result2 = generate_str(test_size);
        assert!(result2.is_ok());
        let result2 = result2.unwrap();
        assert_ne!(result, result2);
    }

    #[test]
    fn test_generate_random() {
        let test_size = 16;
        let result = generate_random(test_size);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), test_size);
        let result2 = generate_random(test_size);
        assert!(result2.is_ok());
        let result2 = result2.unwrap();
        assert_ne!(result, result2);
    }
}