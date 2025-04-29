use crate::token_entity::VerifyTokenResponse;
use crate::token_error::{GenerateTokenError, VerifyTokenError};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use env_config_parse::{yaml_get, YamlValue};
use key_management::api::{CryptoOperations, DefaultCryptoImpl};
use key_management::key_manager::error::KeyManagerError;
use key_management::key_manager::key_initialization::{is_initialized};

/// token manager
pub struct TokenManager;

impl TokenManager {
    async fn get_token_config_value(yaml: &YamlValue, key: &str) -> String {
        yaml_get!(yaml.clone(), String::from("attestation_service.token_management.")+key => str)
            .unwrap_or_else(|| "".parse().unwrap())
    }

    /// generate token
    pub async fn generate_token(json_body: &mut Value) -> Result<String, GenerateTokenError> {
        if !is_initialized() {
            error!("Attempted to generate token with uninitialized key.");
            return Err(GenerateTokenError::GenerateTokenError(
                "Key is not initialized".to_string(),
            ));
        }

        // get_private_key
        let key_info_resp = DefaultCryptoImpl
            .get_private_key("TSK", None)
            .await
            .map_err(|e: KeyManagerError| {
                error!("get_private_key error: {}", e.to_string());
                GenerateTokenError::GenerateTokenError(e.to_string())
            })?;
        let private_key = EncodingKey::from_rsa_pem(&key_info_resp.key).map_err(|e| {
            error!("from_rsa_pem error: {}", e.to_string());
            GenerateTokenError::GenerateTokenError(e.to_string())
        })?;

        // get algorithm
        let algorithm = key_info_resp.algorithm;
        info!("algorithm: {:?}", algorithm);
        if !algorithm.contains("rsa") {
            error!("Wrong key algorithm {}", algorithm);
            return Err(GenerateTokenError::GenerateTokenError(
                "The key algorithm is illegal".to_string(),
            ));
        }

        let yaml = YamlValue::from_default_yaml().map_err(|e| {
            error!("get default yaml error: {}", e.to_string());
            GenerateTokenError::GenerateTokenError(e.to_string())
        })?;
        // define header
        let mut header = Header::new(Algorithm::RS256);
        header.jku = Some(Self::get_token_config_value(&yaml, "jku").await);
        header.kid = Some(Self::get_token_config_value(&yaml, "kid").await);

        // get config value
        let token_exist_time = Self::get_token_config_value(&yaml, "exist_time")
            .await
            .parse::<u128>()
            .map_err(|e| {
                error!("get exist_time error {}", e.to_string());
                GenerateTokenError::GenerateTokenError(e.to_string())
            })?;
        let token_iss = Self::get_token_config_value(&yaml, "iss").await;
        let token_eat_profile = Self::get_token_config_value(&yaml, "eat_profile").await;

        // fill body value
        if let Value::Object(ref mut map) = json_body {
            map.insert(
                "iat".to_string(),
                json!(SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()),
            );
            map.insert(
                "exp".to_string(),
                json!(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis()
                        + token_exist_time
                ),
            );
            map.insert("iss".to_string(), json!(token_iss));
            map.insert("jti".to_string(), json!(Uuid::new_v4().to_string()));
            map.insert("ver".to_string(), json!("1.0"));
            map.insert(
                "nbf".to_string(),
                json!(SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()),
            );
            map.insert("eat_profile".to_string(), json!(token_eat_profile));
        }
        debug!("json_body: {:?}", json_body);

        // generate token
        match encode(&header, &json_body, &private_key) {
            Ok(token) => {
                info!("Generated token success");
                Ok(token)
            }
            Err(e) => {
                error!("Generated token failed: {}", e);
                Err(GenerateTokenError::GenerateTokenError(e.to_string()))
            }
        }
    }

    /// verify token
    pub async fn verify_token(token: &str) -> Result<VerifyTokenResponse, VerifyTokenError> {
        // get_public_key
        let key_info_resp = DefaultCryptoImpl
            .get_public_key("TSK", None)
            .await
            .map_err(|e: KeyManagerError| {
                error!("get_public_key error: {}", e.to_string());
                VerifyTokenError::VerifyTokenError(e.to_string())
            })?;
        let public_key = DecodingKey::from_rsa_pem(&key_info_resp.key).map_err(|e| {
            error!("from_rsa_pem error: {}", e.to_string());
            VerifyTokenError::VerifyTokenError(e.to_string())
        })?;

        // get algorithm
        let algorithm = key_info_resp.algorithm;
        if !algorithm.contains("rsa") {
            error!("Wrong key algorithm {}", algorithm);
            return Err(VerifyTokenError::VerifyTokenError(
                "The key algorithm is illegal".to_string(),
            ));
        }

        // verify token
        match decode::<Value>(&token, &public_key, &Validation::new(Algorithm::RS256)) {
            Ok(token_data) => {
                info!("Token verified successfully");
                Ok(VerifyTokenResponse::new(
                    true,
                    token_data.claims,
                    token_data.header,
                ))
            }
            Err(e) => {
                error!("Token verification failed: {}", e);
                Ok(VerifyTokenResponse::new(
                    false,
                    Value::Null,
                    Header::default(),
                ))
            }
        }
    }
}
