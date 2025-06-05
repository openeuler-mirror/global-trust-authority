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

use crate::token_entity::VerifyTokenResponse;
use crate::token_error::{GenerateTokenError, VerifyTokenError};
use config_manager::types::CONFIG;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use key_management::api::{CryptoOperations, DefaultCryptoImpl};
use key_management::key_manager::error::KeyManagerError;
use key_management::key_manager::key_initialization::is_initialized;
use log::{debug, error, info};
use mq::send_message;
use openssl::pkey::PKey;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// token manager
const MAX_SIZE: usize = 5 * 1024 * 1024;

pub struct TokenManager;

impl TokenManager {
    /// Generates a new token based on the provided JSON body.
    ///
    /// This function retrieves the private key, configures the token header and claims,
    /// and encodes the token. It also optionally sends the generated token to a message queue.
    ///
    /// # Arguments
    /// * `json_body` - A mutable JSON Value containing the claims to be included in the token.
    ///
    /// # Returns
    /// * `Result<String, GenerateTokenError>` - The generated token string if successful,
    ///   or a `GenerateTokenError` if an error occurs during key retrieval, configuration,
    ///   time calculation, or encoding.
    ///
    /// # Error
    /// * `GenerateTokenError` - If the key is not initialized, fails to retrieve keys,
    ///   invalid key algorithm, fails to get config, fails to get system time,
    ///   token expiration time calculation overflowed, or fails to encode the token.
    pub async fn generate_token(json_body: &mut Value) -> Result<String, GenerateTokenError> {
        if !is_initialized() {
            error!("Attempted to generate token with uninitialized key.");
            return Err(GenerateTokenError::GenerateTokenError("Key is not initialized".to_string()));
        }

        // get_private_key
        let key_info_resp = DefaultCryptoImpl.get_private_key("TSK", None).await.map_err(|e: KeyManagerError| {
            error!("get_private_key error: {}", e.to_string());
            GenerateTokenError::GenerateTokenError(e.to_string())
        })?;
        let pkey = PKey::private_key_from_pem(&key_info_resp.key)
            .map_err(|e| GenerateTokenError::GenerateTokenError(e.to_string()))?;
        let rsa = pkey.rsa().map_err(|e| GenerateTokenError::GenerateTokenError(e.to_string()))?;
        let der = rsa.private_key_to_der().unwrap();
        let private_key = EncodingKey::from_rsa_der(&der);

        // get algorithm
        let algorithm = key_info_resp.algorithm;
        info!("algorithm: {:?}", algorithm);
        if !algorithm.contains("rsa") {
            error!("Wrong key algorithm {}", algorithm);
            return Err(GenerateTokenError::GenerateTokenError("The key algorithm is illegal".to_string()));
        }

        // get config
        let config = CONFIG.get_instance().unwrap();
        let token_management = config.attestation_service.token_management.clone();
        // define header
        let mut header = Header::new(Algorithm::RS256);
        header.jku = Some(token_management.jku);
        header.kid = Some(token_management.kid);

        // get config value
        let token_exist_time = token_management.exist_time;
        let token_iss = token_management.iss;
        let token_eat_profile = token_management.eat_profile;

        // fill body value
        let now_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        if let Value::Object(ref mut map) = json_body {
            map.insert("iat".to_string(), json!(now_time));
            map.insert("exp".to_string(), json!(now_time + token_exist_time));
            map.insert("iss".to_string(), json!(token_iss));
            map.insert("jti".to_string(), json!(Uuid::new_v4().to_string()));
            map.insert("ver".to_string(), json!("1.0"));
            map.insert("nbf".to_string(), json!(now_time));
            map.insert("eat_profile".to_string(), json!(token_eat_profile));
        }
        debug!("json_body: {:?}", json_body);

        // generate token
        match encode(&header, &json_body, &private_key) {
            Ok(token) => {
                info!("Generated token success");
                if token.len() > MAX_SIZE {
                    error!("Generated token size exceeds 5M");
                    return Err(GenerateTokenError::GenerateTokenError("Generated token size exceeds 5M".to_string()));
                }
                if token_management.mq_enabled {
                    let token_clone = token.clone();
                    tokio::spawn(async move {
                        send_message(&token_management.token_topic, "token", &token_clone).await;
                    });
                }
                Ok(token)
            },
            Err(e) => {
                error!("Generated token failed: {}", e);
                Err(GenerateTokenError::GenerateTokenError(e.to_string()))
            },
        }
    }

    /// Verifies the authenticity and validity of a given token.
    ///
    /// This function retrieves the public key, decodes and validates the token
    /// using the specified algorithm.
    ///
    /// # Arguments
    /// * `token` - The token string to verify.
    ///
    /// # Returns
    /// * `Result<VerifyTokenResponse, VerifyTokenError>` - A `VerifyTokenResponse`
    ///   indicating the verification result and containing the claims and header if successful,
    ///   or a `VerifyTokenError` if an error occurs during key retrieval or verification.
    ///
    /// # Error
    /// * `VerifyTokenError` - If fails to retrieve public key, invalid key algorithm,
    ///   fails to decode or verify the token.
    pub async fn verify_token(token: &str) -> Result<VerifyTokenResponse, VerifyTokenError> {
        // get_public_key
        let key_info_resp = DefaultCryptoImpl.get_public_key("TSK", None).await.map_err(|e: KeyManagerError| {
            error!("get_public_key error: {}", e.to_string());
            VerifyTokenError::VerifyTokenError(e.to_string())
        })?;
        let pkey = PKey::public_key_from_pem(&key_info_resp.key)
            .map_err(|e| VerifyTokenError::VerifyTokenError(e.to_string()))?;
        let rsa = pkey.rsa().map_err(|e| VerifyTokenError::VerifyTokenError(e.to_string()))?;
        let der = rsa.public_key_to_der_pkcs1().unwrap();
        let public_key = DecodingKey::from_rsa_der(&der);

        // get algorithm
        let algorithm = key_info_resp.algorithm;
        if !algorithm.contains("rsa") {
            error!("Wrong key algorithm {}", algorithm);
            return Err(VerifyTokenError::VerifyTokenError("The key algorithm is illegal".to_string()));
        }

        // verify token
        match decode::<Value>(&token, &public_key, &Validation::new(Algorithm::RS256)) {
            Ok(token_data) => {
                info!("Token verified successfully");
                Ok(VerifyTokenResponse::new(true, token_data.claims, token_data.header))
            },
            Err(e) => {
                error!("Token verification failed: {}", e);
                Ok(VerifyTokenResponse::new(false, Value::Null, Header::default()))
            },
        }
    }
}
