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

use std::string::String;
use actix_web::Result;
use base64::{engine::general_purpose::{self, STANDARD}, Engine as _};
use chrono::Utc;
use sea_orm::{ActiveValue::Set, DatabaseConnection, TryIntoModel};
use serde_json::Value;
use uuid::Uuid;
use crate::entities::{
    policy::Policy,
    policy_db_model::{ActiveModel, Model},
    signature_policy::SignaturePolicy,
};
use crate::error::policy_error::PolicyError;
use crate::repositories::policy_repository::PolicyRepository;
use crate::constants::{POLICY_CERT_TYPE, SIGNATURE_KEY_TYPE};
use key_management::api::{
    crypto_operations::CryptoOperations,
    impls::default_crypto_impl::DefaultCryptoImpl,
    SignResponse,
};
use endorserment::services::cert_service::CertService;
use common_log::{error, info, warn};
use plugin_manager::{PluginManager, PluginManagerInstance, ServicePlugin, ServiceHostFunctions};
use jwt::jwt_parser::JwtParser;
use config_manager::types::context::CONFIG;

pub struct PolicyHandler;

impl PolicyHandler {
    /// Decodes policy content based on the content type (text or JWT).
    ///
    /// # Arguments
    /// * `content` - Base64 encoded policy content
    /// * `content_type` - Type of content ("text" or "jwt")
    ///
    /// # Returns
    /// * `Result<String, PolicyError>` - Decoded policy content if successful
    /// * `PolicyContentSizeLimitReached` - If the decoded content exceeds the size limit
    /// * `IncorrectFormatError` - If the content cannot be decoded or has invalid format
    fn decode_policy_content(content: String, content_type: &str) -> Result<String, PolicyError> {
        let config = CONFIG.get_instance().unwrap();
        let check_content_size = |decoded_content: &str| {
            let max_size_kb = config.attestation_service.policy.policy_content_size_limit as usize;
            if decoded_content.len() > max_size_kb * 1024 {
                return Err(PolicyError::PolicyContentSizeLimitReached(format!(
                    "Policy content size exceeds {} KB limit",
                    max_size_kb
                )));
            }
            Ok(decoded_content.to_string())
        };

        if content_type == "text" {
            STANDARD
                .decode(&content)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .map_err(|_| PolicyError::IncorrectFormatError("Failed to decode base64 content".to_string()))
                .and_then(|decoded| check_content_size(&decoded))
        } else if content_type == "jwt" {
            Self::validate_jwt_content(&content)?;
            let parts: Vec<&str> = content.split('.').collect();
            let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
                .map_err(|_| PolicyError::IncorrectFormatError("Failed to decode JWT payload".to_string()))
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map_err(|_| PolicyError::IncorrectFormatError("JWT payload is not valid UTF-8".to_string()))
                })?;

            let token_data: Value = serde_json::from_str(&payload).map_err(|e| {
                PolicyError::IncorrectFormatError(format!("Failed to parse JWT payload as JSON: {}", e))
            })?;

            let decoded_content = token_data
                .get("policy")
                .and_then(|v| v.as_str())
                .map(|policy| {
                    STANDARD.decode(policy).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).map_err(|_| {
                        PolicyError::IncorrectFormatError("Failed to decode policy content in JWT".to_string())
                    })
                })
                .transpose()?
                .unwrap_or(content);
            check_content_size(&decoded_content)
        } else {
            Err(PolicyError::IncorrectFormatError("Unsupported content type".to_string()))
        }
    }

    fn validate_jwt_content(jwt_content: &str) -> Result<(), PolicyError> {
        let parts: Vec<&str> = jwt_content.split('.').collect();
        if parts.len() != 3 {
            return Err(PolicyError::IncorrectFormatError("JWT must have three parts separated by dots".into()));
        }

        let header_json = match general_purpose::URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(text) => match serde_json::from_str::<Value>(&text) {
                    Ok(json) => json,
                    Err(_) => return Err(PolicyError::IncorrectFormatError("JWT header is not valid JSON".into())),
                },
                Err(_) => return Err(PolicyError::IncorrectFormatError("JWT header is not valid UTF-8".into())),
            },
            Err(_) => return Err(PolicyError::IncorrectFormatError("Invalid JWT header".into())),
        };
        Self::validate_jwt_fields(&header_json, "alg", "header")?;

        // Validate payload section
        let payload_json = match general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(text) => match serde_json::from_str::<Value>(&text) {
                    Ok(json) => json,
                    Err(_) => return Err(PolicyError::IncorrectFormatError("JWT payload is not valid JSON".into())),
                },
                Err(_) => return Err(PolicyError::IncorrectFormatError("JWT payload is not valid UTF-8".into())),
            },
            Err(_) => return Err(PolicyError::IncorrectFormatError("Invalid JWT payload".into())),
        };
        Self::validate_jwt_fields(&payload_json, "policy", "payload")?;

        Ok(())
    }

    fn validate_jwt_fields(json: &Value, field: &str, section: &str) -> Result<(), PolicyError> {
        if !json.get(field).is_some() {
            return Err(PolicyError::IncorrectFormatError(
                format!("JWT {} must contain '{}' field", section, field).into(),
            ));
        }
        Ok(())
    }

    /// Creates a new policy object from request data.
    ///
    /// # Arguments
    /// * `headers` - HTTP headers containing user information
    /// * `request_body` - JSON payload with policy details
    /// * `db` - Database connection for checking policy existence
    ///
    /// # Returns
    /// * `Result<Policy, PolicyError>` - Created policy object if successful
    /// * `IncorrectFormatError` - If the content cannot be decoded or has invalid format
    /// * `PolicyExistError` - If a policy with the same ID or name already exists
    /// * `DatabaseOperationError` - If there is an error during database operation
    pub async fn create_policy(
        headers: &actix_web::http::header::HeaderMap,
        request_body: &Value,
        db: &DatabaseConnection,
    ) -> Result<Policy, PolicyError> {
        let user_id = headers
            .get("User-Id")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("system")
            .to_string();
        let name = request_body["name"].as_str().unwrap().to_string();
        let content_type = request_body["content_type"].as_str().unwrap().to_string();
        let content = request_body["content"].as_str().unwrap().to_string();
        let content = Self::decode_policy_content(content, &content_type)?;
        let id = request_body
            .get("id")
            .and_then(|id| id.as_str())
            .unwrap_or(Uuid::new_v4().to_string().as_str())
            .to_string();
        let description = request_body
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let attester_type = request_body["attester_type"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let is_default = request_body
            .get("is_default")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Self::check_policy_existence(&db, &user_id, &name, &id).await?;
        let policy = Policy::new(id, name, description, content, attester_type, Some(is_default));

        Ok(policy)
    }

    /// Checks if a policy with the given ID or name already exists.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user who owns the policy
    /// * `name` - Name of the policy to check
    /// * `id` - ID of the policy to check
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if no policy exists with the given ID or name
    /// * `PolicyExistError` - If a policy with the same ID or name already exists
    /// * `DatabaseOperationError` - If there is an error during database operation
    async fn check_policy_existence(
        db: &DatabaseConnection,
        user_id: &str,
        name: &str,
        id: &str,
    ) -> Result<(), PolicyError> {
        let config = CONFIG.get_instance().unwrap();
        let policy_limit = config.attestation_service.policy.single_user_policy_limit;
        // Check policy limit
        match PolicyRepository::get_all_policies(db, user_id.to_string()).await {
            Ok(policies) => {
                if policies.len() >= policy_limit as usize {
                    error!("User '{}' has reached the policy limit of {}", user_id, policy_limit);
                    return Err(PolicyError::PolicyLimitReached(format!(
                        "User has reached the maximum number of policies ({})",
                        policy_limit
                    )));
                }
            },
            Err(e) => {
                error!("Database error when checking policy limit: {:?}", e);
                return Err(PolicyError::DatabaseOperationError(e.to_string()));
            },
        }

        // Check policy ID existence
        match PolicyRepository::check_policy_exist_use_id(db, id.to_string()).await {
            Ok(Some(_)) => {
                error!("Policy with ID '{}' already exists", id);
                return Err(PolicyError::PolicyExistError(format!("Policy ID '{}' already exists", id)));
            },
            Err(e) => {
                error!("Database error when checking policy ID existence: {:?}", e);
                return Err(PolicyError::DatabaseOperationError(e.to_string()));
            },
            Ok(None) => {},
        }

        // Check policy name existence
        match PolicyRepository::check_policy_exist_policy_name(db, user_id.to_string(), name.to_string()).await {
            Ok(Some(_)) => {
                error!("Policy with name '{}' already exists for user '{}'", name, user_id);
                return Err(PolicyError::PolicyExistError(format!("Policy name '{}' already exists", name)));
            },
            Err(e) => {
                error!("Database error when checking policy name existence: {:?}", e);
                return Err(PolicyError::DatabaseOperationError(e.to_string()));
            },
            Ok(None) => {},
        }

        Ok(())
    }

    /// Creates a database model from a policy object.
    ///
    /// # Arguments
    /// * `headers` - HTTP headers containing user information
    /// * `policy` - Policy object to convert to database model
    ///
    /// # Returns
    /// * `ActiveModel` - Database model ready for insertion
    pub fn create_policy_model(
        headers: &actix_web::http::header::HeaderMap,
        policy: &Policy
    ) -> ActiveModel {
        let user_id = headers
            .get("User-Id")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("system")
            .to_string();

        let mut policy_model: ActiveModel = policy.clone().into();
        policy_model.user_id = sea_orm::Set(user_id);

        policy_model
    }

    /// Builds an update model for an existing policy based on request data.
    ///
    /// # Arguments
    /// * `request_body` - JSON payload with fields to update
    /// * `policy` - Existing policy model to update
    ///
    /// # Returns
    /// * `Result<ActiveModel, PolicyError>` - Updated policy model if successful
    /// * `IncorrectFormatError` - If the content cannot be decoded or has invalid format
    /// * `PolicyVersionOverflowError` - If the policy version has reached the maximum value
    /// * `DatabaseOperationError` - If there is an error during database operation
    pub async fn build_update_model(
        request_body: &Value,
        policy: &Model,
    ) -> Result<ActiveModel, PolicyError> {
        let mut model = ActiveModel::default();
        macro_rules! update_field {
            ($field:ident, $body_key:expr, $type:ty) => {
                model.$field = match request_body.get($body_key) {
                    Some(value) if !value.is_null() => {
                        if let Some(str_value) = value.as_str() {
                            Set(str_value.to_string())
                        } else {
                            Set(policy.$field.clone())
                        }
                    },
                    _ => Set(policy.$field.clone()),
                };
            };
            ($field:ident, $body_key:expr, $type:ty, $convert:expr) => {
                model.$field = match request_body.get($body_key) {
                    Some(value) if !value.is_null() => {
                        if let Some(arr) = value.as_array() {
                            let converted = arr
                                .iter()
                                .filter_map($convert)
                                .collect::<Vec<_>>();
                            Set(serde_json::to_value(converted)
                                .map_err(|e| PolicyError::IncorrectFormatError(e.to_string()))?)
                        } else {
                            Set(policy.$field.clone())
                        }
                    },
                    _ => Set(policy.$field.clone()),
                };
            };
        }

        update_field!(policy_id, "id", str);
        update_field!(policy_name, "name", str);
        update_field!(policy_description, "description", str);
        update_field!(attester_type, "attester_type", array, |v| v.as_str().map(String::from));
        model.policy_content = if let Some(content) = request_body.get("content").and_then(|v| v.as_str()) {
            let content_type = request_body.get("content_type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PolicyError::IncorrectFormatError("content_type is required when content is provided".to_string()))?;
            Set(Self::decode_policy_content(content.to_string(), content_type)?)
        } else {
            Set(policy.policy_content.clone())
        };
        model.is_default = Set(request_body
            .get("is_default")
            .and_then(|v| v.as_bool())
            .unwrap_or(policy.is_default));
        model.update_time = Set(Utc::now().timestamp());
        let current_version =
            PolicyRepository::get_policy_version(model.policy_id.clone().unwrap()).await?;
        model.policy_version = Set((current_version + 1i32).try_into().unwrap());
        model.create_time = Set(policy.create_time);
        model.user_id = Set(policy.user_id.clone());
        model.signature = Set(policy.signature.clone());
        model.valid_code = Set(policy.valid_code);
        model.key_version = Set(policy.key_version.clone());
        model.product_name = sea_orm::Set(String::new());
        model.product_type = sea_orm::Set(String::new());
        model.board_type = sea_orm::Set(String::new());

        Ok(model)
    }


    /// Verifies the signature of an existing policy and signs the updated policy if required.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `policy` - Existing policy model with signature to verify
    /// * `update_model` - Updated policy model to sign
    ///
    /// # Returns
    /// * `Result<ActiveModel, PolicyError>` - Signed policy model if successful
    /// * `PolicySignatureFailure` - If the existing policy signature verification fails
    /// * `DatabasePolicySignatureError` - If there is an error during signature verification
    pub async fn verify_and_sign_policy(
        db: &DatabaseConnection,
        policy: &Model,
        update_model: ActiveModel,
    ) -> Result<ActiveModel, PolicyError> {
        let config = CONFIG.get_instance().unwrap();
        let is_require_sign = config.attestation_service.key_management.is_require_sign;
        if !is_require_sign {
            return Ok(update_model);
        }

        let signature_policy = SignaturePolicy::from(policy.clone());
        match Self::verify_policy_signature(db, &signature_policy).await {
            Ok(true) => {
                PolicyHandler::verify_policy_content_is_valid(signature_policy.clone())?;
                match Self::sign_policy(update_model).await {
                    Ok(model) => Ok(model),
                    Err(e) => {
                        error!("Failed to sign updated policy: {:?}", e);
                        Err(e)
                    },
                }
            },
            Ok(false) => {
                error!("Policy signature verification failed!");
                Err(PolicyError::PolicySignatureFailure("Policy signature verification failed".to_string()))
            },
            Err(e) => {
                error!("Policy signature verification failed: {:?}", e);
                Err(e)
            },
        }
    }

    /// Signs a policy model with a digital signature.
    ///
    /// # Arguments
    /// * `policy_model` - Policy model to sign
    ///
    /// # Returns
    /// * `Result<ActiveModel, PolicyError>` - Signed policy model with signature and key version
    /// * `PolicySignatureFailure` - If the signing operation fails
    pub async fn sign_policy(mut policy_model: ActiveModel) -> Result<ActiveModel, PolicyError> {
        info!("Start to sign policy!");
        let policy_sign_model: SignaturePolicy = policy_model.clone().try_into_model().unwrap().into();
        let data = policy_sign_model.encode_to_bytes();
        let crypto_ops = DefaultCryptoImpl;
        match crypto_ops.sign(&data, SIGNATURE_KEY_TYPE).await {
            Ok(SignResponse { signature, key_version }) => {
                policy_model.signature = Set(signature);
                policy_model.key_version = Set(key_version);
                info!("Sign policy success!");
                Ok(policy_model)
            },
            Err(e) => {
                error!("Failed to sign policy: {:?}", e);
                Err(PolicyError::PolicySignatureFailure(e.to_string()))
            },
        }
    }

    /// Retrieves all policies for a specific user.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user whose policies to retrieve
    ///
    /// # Returns
    /// * `Result<Vec<Policy>, PolicyError>` - List of policies if successful
    /// * `DatabaseOperationError` - If there is an error during database operation
    /// * `DatabasePolicySignatureError` - If there is an error during signature verification
    pub async fn get_all_policies(
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<Vec<Policy>, PolicyError> {
        info!("Query all user policy!");
        let sign_policies = PolicyRepository::get_all_policies(db, user_id).await?;
        let config = CONFIG.get_instance().unwrap();
        let is_require_sign = config.attestation_service.key_management.is_require_sign;
        let mut verify_policies = sign_policies;
        if is_require_sign {
            verify_policies = Self::verify_policies_signature(verify_policies, db).await?;
        }
        verify_policies.sort_by(|a, b| b.update_time.cmp(&a.update_time));
        let policies: Vec<Policy> = verify_policies
            .into_iter()
            .map(|sp| sp.into())
            .collect();

        Ok(policies)
    }

    /// Queries policies by their IDs for a specific user.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `request_body` - JSON payload containing the "ids" field with comma-separated policy IDs
    /// * `user_id` - ID of the user whose policies to query
    ///
    /// # Returns
    /// * `Result<Vec<Policy>, PolicyError>` - List of matching policies if successful
    /// * `DatabaseOperationError` - If there is an error during database operation
    /// * `DatabasePolicySignatureError` - If there is an error during signature verification
    pub async fn query_policies_by_ids(
        db: &DatabaseConnection,
        request_body: &Value,
        user_id: String,
    ) -> Result<Vec<Policy>, PolicyError> {
        info!("Query policy by ids!");
        use std::collections::HashSet;
        let policy_ids: Vec<String> = request_body["ids"]
            .as_str()
            .map(|s| s.split(','))
            .unwrap_or_else(|| "".split(','))
            .map(|id| id.trim())
            .filter(|id_str| !id_str.is_empty())
            .map(|id| {
                String::from_utf8(id.as_bytes().to_vec())
                    .unwrap_or_else(|_| id.to_string())
            })
            .collect::<HashSet<String>>()
            .into_iter()
            .collect();
        let sign_policies = PolicyRepository::get_policies_by_ids(db, policy_ids, user_id).await?;
        let config = CONFIG.get_instance().unwrap();
        let is_require_sign = config.attestation_service.key_management.is_require_sign;
        let mut verify_policies = sign_policies;
        if is_require_sign {
            verify_policies = Self::verify_policies_signature(verify_policies, db).await?;
        }
        verify_policies.sort_by(|a, b| b.update_time.cmp(&a.update_time));
        let policies: Vec<Policy> = verify_policies
            .into_iter()
            .map(|sp| sp.into())
            .collect();
        Ok(policies)
    }

    /// Queries policies by attester type for a specific user.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `request_body` - JSON payload containing the "attester_type" field
    /// * `user_id` - ID of the user whose policies to query
    ///
    /// # Returns
    /// * `Result<Vec<Policy>, PolicyError>` - List of matching policies if successful
    /// * `IncorrectFormatError` - If the attester_type is not a string
    /// * `DatabaseOperationError` - If there is an error during database operation
    /// * `DatabasePolicySignatureError` - If there is an error during signature verification
    pub async fn query_policies_by_type(
        db: &DatabaseConnection,
        request_body: &Value,
        user_id: String,
    ) -> Result<Vec<Policy>, PolicyError> {
        info!("Query policy by attester_type!");
        let attester_type = request_body["attester_type"]
            .as_str()
            .map(|s| s.trim())
            .ok_or_else(|| PolicyError::IncorrectFormatError("attester_type must be a string".to_string()))?;
        let sign_policies = PolicyRepository::get_policies_by_type(db, attester_type.to_string(), user_id).await?;
        let config = CONFIG.get_instance().unwrap();
        let is_require_sign = config.attestation_service.key_management.is_require_sign;
        let mut verify_policies = sign_policies;
        if is_require_sign {
            verify_policies = Self::verify_policies_signature(verify_policies, db).await?;
        }
        verify_policies.sort_by(|a, b| b.update_time.cmp(&a.update_time));
        let policies: Vec<Policy> = verify_policies
            .into_iter()
            .map(|sp| sp.into())
            .collect();

        Ok(policies)
    }

    /// Verifies the signatures of multiple policies.
    ///
    /// # Arguments
    /// * `sign_policies` - List of policies with signatures to verify
    /// * `db` - Database connection for updating policy status if verification fails
    ///
    /// # Returns
    /// * `Result<Vec<SignaturePolicy>, PolicyError>` - List of policies with verification status
    /// * `DatabasePolicySignatureError` - If there is an error during signature verification
    /// * `DatabaseOperationError` - If there is an error updating policy status
    async fn verify_policies_signature(
        sign_policies: Vec<SignaturePolicy>,
        db: &DatabaseConnection,
    ) -> Result<Vec<SignaturePolicy>, PolicyError> {
        let crypto_impl = DefaultCryptoImpl;
        let mut verify_policies = Vec::new();

        for mut sign_policy in sign_policies {
            if sign_policy.valid_code == 0 {
                let data = sign_policy.encode_to_bytes();
                match crypto_impl
                    .verify(SIGNATURE_KEY_TYPE, Some(&sign_policy.key_version), data, sign_policy.signature.clone())
                    .await
                {
                    Ok(true) => {
                        verify_policies.push(sign_policy);
                    },
                    Ok(false) => {
                        PolicyRepository::set_is_corrupted(db, sign_policy.policy_id.clone()).await?;
                        sign_policy.valid_code = 1;
                        verify_policies.push(sign_policy);
                    },
                    Err(e) => {
                        error!("Failed to verify policy signature: {:?}", e);
                        return Err(PolicyError::DatabasePolicySignatureError(e.to_string()));
                    },
                }
            } else {
                verify_policies.push(sign_policy);
            }
        }

        Ok(verify_policies)
    }

    /// Verifies the signature of a single policy.
    ///
    /// # Arguments
    /// * `db` - Database connection for updating policy status if verification fails
    /// * `signature_policy` - Policy with signature to verify
    ///
    /// # Returns
    /// * `Result<bool, PolicyError>` - True if signature is valid, False if invalid
    /// * `DatabasePolicySignatureError` - If there is an error during signature verification
    /// * `DatabaseOperationError` - If there is an error updating policy status
    pub async fn verify_policy_signature(
        db: &DatabaseConnection,
        signature_policy: &SignaturePolicy,
    ) -> Result<bool, PolicyError> {
        let crypto_impl = DefaultCryptoImpl;
        let data = signature_policy.encode_to_bytes();
        match crypto_impl
            .verify(SIGNATURE_KEY_TYPE, Some(&signature_policy.key_version), data, signature_policy.signature.clone())
            .await
        {
            Ok(true) => Ok(true),
            Ok(false) => {
                PolicyRepository::set_is_corrupted(db, signature_policy.policy_id.clone())
                    .await
                    .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
                Ok(false)
            },
            Err(e) => {
                warn!("Failed to validate the policy signature taken out of the database: {:?}", e);
                Err(PolicyError::DatabasePolicySignatureError(e.to_string()))
            },
        }
    }

    /// Verifies the JWT signature using a certificate.
    ///
    /// # Arguments
    /// * `request_body` - JSON payload containing content_type and content fields
    /// * `user_id` - ID of the user for certificate verification
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if signature is valid or verification is not required
    /// * `IncorrectFormatError` - If the content has invalid format or text content type with verification enabled
    /// * `PolicySignatureVerificationError` - If the signature verification fails
    pub async fn verify_signature_by_cert(
        request_body: &Value,
        user_id: String,
    ) -> Result<(), PolicyError> {
        let content_type = request_body["content_type"]
            .as_str()
            .ok_or_else(|| PolicyError::IncorrectFormatError("content_type is required".to_string()))?;
        let content = request_body["content"]
            .as_str()
            .ok_or_else(|| PolicyError::IncorrectFormatError("content is required".to_string()))?;
        let config = CONFIG.get_instance().unwrap();
        let is_verify_policy_signature = config.attestation_service.policy.is_verify_policy_signature;
        if content_type == "jwt" && is_verify_policy_signature {
            let parts: Vec<&str> = content.splitn(3, '.').collect();
            if parts.len() != 3 {
                return Err(PolicyError::IncorrectFormatError("Invalid JWT format".to_string()));
            }
            let alg = JwtParser::get_alg(content).map_err(|e| PolicyError::InvalidPolicyContent(e.to_string()))?;
            let signature = JwtParser::get_signature(content).map_err(|e| PolicyError::InvalidPolicyContent(e.to_string()))?;
            let base_data = JwtParser::get_base_data(content);
            let verify_result = CertService::verify_by_cert(
                POLICY_CERT_TYPE,
                user_id.as_str(),
                &signature,
                alg,
                &base_data.as_bytes(),
            )
            .await
            .map_err(|e| PolicyError::PolicySignatureVerificationError(e.to_string()))?;
            if !verify_result {
                return Err(PolicyError::PolicySignatureVerificationError("Can not verify certificate".to_string()));
            }
            Ok(())
        } else if content_type == "text" && is_verify_policy_signature {
            Err(PolicyError::IncorrectFormatError(
                "text content type does not support signature verification".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn verify_policy_content_is_valid<T>(policy_input: T) -> Result<(), PolicyError>
    where
        T: Into<Policy>
    {
        let policy: Policy = policy_input.into();
        let manager = PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance();

        for attester_type in &policy.attester_type {
            let plugin = match manager.get_plugin(attester_type) {
                Some(p) => p,
                None => return Err(PolicyError::PolicyMatchSyntaxError(format!("Plugin not found for attester type: {}", attester_type))),
            };
            let sample_output = plugin.get_sample_output();
            match policy_engine::evaluate_policy(&sample_output, &policy.content) {
                Ok(_) => return Ok(()),
                Err(engine_err) => {
                    return Err(PolicyError::PolicyMatchSyntaxError(engine_err.to_string()));
                }
            }
        }

        Err(PolicyError::PolicyMatchSyntaxError("No valid attester type found".to_string()))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_policy_content_text() {
        let content = STANDARD.encode("test content");
        let result = PolicyHandler::decode_policy_content(content, "text");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test content");
    }
}
