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
    use rand::distributions::Alphanumeric;
    use rand::{Rng, RngCore};
    use rand::rngs::OsRng;
    use ring::digest::SHA256_OUTPUT_LEN;
    use ring::pbkdf2::PBKDF2_HMAC_SHA256;
    use ring::pbkdf2;
    use uuid::Uuid;
    use crate::error::register_error::RegisterError;
    
    static APIKEY_LENGTH: usize = 32; 
    static SALT_LENGTH: usize = 16;
    static PBKDF2_SIZE: u32 = 10000;

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
        info.apikey = generate_str(APIKEY_LENGTH);
        info.salt = generate_random(SALT_LENGTH);
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
        apikey.apikey = generate_str(APIKEY_LENGTH);
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
    
    pub fn generate_str(size: usize) -> String {
        OsRng
            .sample_iter(&Alphanumeric)
            .take(size)
            .map(char::from)
            .collect()
    }

    pub fn generate_random(size: usize) -> Vec<u8> {
        let mut key = vec![0u8; size];
        OsRng.fill_bytes(&mut key);
        key
    }
}