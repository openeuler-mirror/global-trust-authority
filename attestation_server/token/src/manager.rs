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

use crate::entity::VerifyTokenResponse;
use crate::error::{TokenGenerationError, TokenVerificationError};
use config_manager::types::CONFIG;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::ErrorKind};
use key_management::api::{CryptoOperations, DefaultCryptoImpl};
use key_management::key_manager::error::KeyManagerError;
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
    /// * `Result<String, TokenGenerationError>` - The generated token string if successful,
    ///   or a `TokenGenerationError` if an error occurs during key retrieval, configuration,
    ///   time calculation, or encoding.
    ///
    /// # Errors
    /// * `TokenGenerationError` - If the key is not initialized, fails to retrieve keys,
    ///   invalid key algorithm, fails to get config, fails to get system time,
    ///   token size exceeds limit, or fails to encode the token.
    pub async fn generate_token(json_body: &mut Value) -> Result<String, TokenGenerationError> {
        // get_private_key
        let key_info_resp = DefaultCryptoImpl.get_private_key("TSK", None).await.map_err(|e: KeyManagerError| {
            error!("get_private_key error: {}", e.to_string());
            TokenGenerationError::InternalServerError})?;
        let pkey = PKey::private_key_from_pem(&key_info_resp.key).map_err(|e| {
            error!("Failed to convert private key to PKey: {}", e);
            TokenGenerationError::InternalServerError})?;
        // only rsa is currently supported
        let rsa = pkey.rsa().map_err(|e| {
            error!("Failed to convert private key to RSA: {}", e);
            TokenGenerationError::InternalServerError})?;
        let der = rsa.private_key_to_der().map_err(|e| {
            error!("Failed to convert private key to DER: {}", e);
            TokenGenerationError::InternalServerError})?;
        let private_key = EncodingKey::from_rsa_der(&der);

        // get config
        let config = CONFIG.get_instance().map_err(|e| {
            error!("Failed to get config: {}", e);
            TokenGenerationError::InternalServerError})?;
        let token_management_config = &config.attestation_service.token_management;
        // define header
        let mut header = Header::new(Self::get_algorithm(token_management_config.token_signing_algorithm.as_str()));
        header.jku = Some(token_management_config.jku.clone());
        header.kid = Some(token_management_config.kid.clone());

        // fill body value
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
            error!("Failed to get system time: {}", e);
            TokenGenerationError::InternalServerError})?.as_secs();
        if let Value::Object(ref mut map) = json_body {
            map.insert("iat".to_string(), json!(current_time));
            map.insert("exp".to_string(), json!(current_time.saturating_add(token_management_config.exist_time)));
            map.insert("iss".to_string(), json!(token_management_config.iss));
            map.insert("jti".to_string(), json!(Uuid::new_v4().to_string()));
            map.insert("ver".to_string(), json!("1.0"));
            map.insert("nbf".to_string(), json!(current_time));
            map.insert("eat_profile".to_string(), json!(token_management_config.eat_profile));
        }
        debug!("json_body: {:?}", json_body);

        // generate token
        match encode(&header, &json_body, &private_key) {
            Ok(token) => {
                if token.len() > MAX_SIZE {
                    error!("Token size exceeds 5M");
                    return Err(TokenGenerationError::TokenSizeError);
                }
                if token_management_config.mq_enabled {
                    let token_clone = token.clone();
                    tokio::spawn(async move {
                        send_message(&token_management_config.token_topic, "token", &token_clone).await;
                    });
                }
                Ok(token)
            },
            Err(e) => {
                error!("Token generation failed: {}", e);
                Err(TokenGenerationError::InternalServerError)
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
    /// * `Result<VerifyTokenResponse, TokenVerificationError>` - A `VerifyTokenResponse`
    ///   indicating the verification result and containing the claims and header if successful,
    ///   or a `TokenVerificationError` if an error occurs during key retrieval or verification.
    ///
    /// # Errors
    /// * `TokenVerificationError` - If fails to retrieve public key, invalid key algorithm,
    ///   fails to decode or verify the token.
    pub async fn verify_token(token: &str) -> Result<VerifyTokenResponse, TokenVerificationError> {
        // get_public_key
        let key_info_resp = DefaultCryptoImpl.get_public_key("TSK", None).await.map_err(|e: KeyManagerError| {
            error!("get_public_key error: {}", e.to_string());
            TokenVerificationError::InternalServerError
        })?;
        let pkey = PKey::public_key_from_pem(&key_info_resp.key)
            .map_err(|e| {
                error!("Failed to convert public key to PKey: {}", e);
                TokenVerificationError::InternalServerError
            })?;
        // only rsa is currently supported
        let rsa = pkey.rsa().map_err(|e| {
            error!("Failed to convert public key to RSA: {}", e);
            TokenVerificationError::InternalServerError
        })?;
        let der = match rsa.public_key_to_der_pkcs1() {
            Ok(der) => der,
            Err(e) => {
                error!("Failed to convert public key to DER: {}", e);
                return Err(TokenVerificationError::InternalServerError);
            }
        };
        let public_key = DecodingKey::from_rsa_der(&der);
        // get config
        let config = CONFIG.get_instance().map_err(|e| {
            error!("Failed to get config: {}", e);
            TokenVerificationError::InternalServerError})?;
        let token_management_config = &config.attestation_service.token_management;
        let algorithm = Self::get_algorithm(token_management_config.token_signing_algorithm.as_str());
        // verify token
        match decode::<Value>(&token, &public_key, &Validation::new(algorithm)) {
            Ok(token_data) => {
                info!("Token verified successfully");
                Ok(VerifyTokenResponse::new(true, None, Some(token_data.claims), Some(token_data.header)))
            },
            Err(e) => {
                let message = match e.kind() {
                    ErrorKind::InvalidSignature | ErrorKind::InvalidToken => Some(String::from(
                        "Token verification failed because either it was not issued by GTA or its signing key is expired/revoked.")),
                    ErrorKind::ImmatureSignature  => Some(String::from("Token is immature.")),
                    ErrorKind::ExpiredSignature => Some(String::from("Token is expired.")),
                    _ => None,
                };
                error!("Token verification failed: {}", e);
                match message {
                    Some(msg) => Ok(VerifyTokenResponse::new(false, Some(msg), None, None)),
                    None => Err(TokenVerificationError::InternalServerError),
                }
            },
        }
    }

    fn get_algorithm(algorithm: &str) -> Algorithm {
        match algorithm {
            "PS256" => Algorithm::PS256,
            "PS384" => Algorithm::PS384,
            "PS512" => Algorithm::PS512,
            _ => Algorithm::PS256,
        }
    }
}
