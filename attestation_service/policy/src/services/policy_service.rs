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

use crate::{
    entities::policy_db_model::ActiveModel,
    handler::policy_handler::PolicyHandler,
    error::policy_error::PolicyError,
    repositories::policy_repository::PolicyRepository,
    util::parameter_filter::ParameterFilter,
    entities::policy_request::{PolicyAddRequest, PolicyUpdateRequest, PolicyDeleteRequest},
};
use actix_web::web::Query;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use sea_orm::{DatabaseConnection, IntoActiveModel, TryIntoModel};
use serde_json;
use serde_json::Value;
use validator::Validate;
use std::sync::Arc;
use common_log::{error, info};
use config_manager::types::CONFIG;

pub struct PolicyService;
impl PolicyService {
    /// Adds a new policy to the system.
    ///
    /// # Arguments
    /// * `req` - The HTTP request containing headers with user information
    /// * `db` - Database connection wrapped in Arc for thread safety
    /// * `request_body` - JSON payload containing policy details with required fields:
    ///   - name: Policy name
    ///   - description: Policy description (optional)
    ///   - attester_type: Array of attester types
    ///   - content_type: Type of content (jwt or text)
    ///   - content: Base64 encoded policy content
    ///   - is_default: Whether this is a default policy (optional, defaults to false)
    ///   - id: Policy ID (optional, generated if not provided)
    ///
    /// # Returns
    /// * `Ok(HttpResponse)` - Success response with policy ID, name, and version
    /// * `Err(PolicyError)` - Various error types including validation, database, or signing errors
    pub async fn add_policy(
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        request_body: web::Json<Value>,
    ) -> Result<HttpResponse, PolicyError> {
        info!("Handling request to add policy");
        let json_string = request_body.to_string();
        let req_body: PolicyAddRequest = serde_json::from_str(&json_string)
            .map_err(|err| PolicyError::IncorrectFormatError(format!("JSON body error: {}", err)))?;
        req_body.validate().map_err(|e| PolicyError::IncorrectFormatError(e.to_string()))?;
        let headers = req.headers();
        let user_id = headers.get("User-Id").and_then(|h| h.to_str().ok()).unwrap_or("system").to_string();
        PolicyHandler::verify_signature_by_cert(&request_body, user_id.clone()).await?;
        let policy = match PolicyHandler::create_policy(headers, &request_body, &db).await {
            Ok(policy) => policy,
            Err(e) => {
                error!("Failed to create policy: {:?}", e);
                return Err(e);
            },
        };
        PolicyHandler::verify_policy_content_is_valid(policy.clone())?;
        let mut policy_model = PolicyHandler::create_policy_model(headers, &policy);
        let is_require_sign = CONFIG.get_instance()?.attestation_service.key_management.is_require_sign;
        if is_require_sign {
            policy_model = ActiveModel::from(
                PolicyHandler::sign_policy(policy_model.into_active_model())
                    .await
                    .map_err(|e| e)?
                    .try_into_model()
                    .unwrap(),
            );
        }
        let policy_limit = CONFIG.get_instance()?.attestation_service.policy.single_user_policy_limit as u64;
        match PolicyRepository::add_policy(&db, policy_model, policy_limit).await {
            Ok(_) => {
                info!("Policy added successfully");
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "policy": {
                        "id": policy.id,
                        "name": policy.name,
                        "version": policy.version
                    }
                })))
            },
            Err(e) => {
                error!("Failed to add policy: {:?}", e);
                match e {
                    PolicyError::PolicyLimitReached(msg) => Err(PolicyError::PolicyLimitReached(msg)),
                    _ => Err(PolicyError::TooManyRequestsError(e.to_string()))
                }
            },
        }
    }

    /// Updates an existing policy in the system.
    ///
    /// # Arguments
    /// * `req` - The HTTP request containing headers with user information
    /// * `db` - Database connection wrapped in Arc for thread safety
    /// * `request_body` - JSON payload containing policy update details with required field:
    ///   - id: Policy ID to update
    ///   Optional fields that can be updated:
    ///   - name: New policy name
    ///   - description: New policy description
    ///   - attester_type: New array of attester types
    ///   - content_type: New type of content (required if content is provided)
    ///   - content: New base64 encoded policy content
    ///   - is_default: New default status
    ///
    /// # Returns
    /// * `Ok(HttpResponse)` - Success response with updated policy ID, name, and version
    /// * `Err(PolicyError)` - Various error types including not found, validation, database, or signing errors
    pub async fn update_policy(
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        request_body: web::Json<Value>,
    ) -> Result<HttpResponse, PolicyError> {
        info!("Handling request to update policy");
        let headers = req.headers();
        let json_string = request_body.to_string();
        let req_body: PolicyUpdateRequest = serde_json::from_str(&json_string)
            .map_err(|err| PolicyError::IncorrectFormatError(format!("JSON body error: {}", err)))?;
        req_body.validate().map_err(|e| PolicyError::IncorrectFormatError(e.to_string()))?;
        let policy = match PolicyRepository::check_policy_exists(headers, &request_body).await {
            Ok(None) => {
                error!("Policy not found!");
                return Err(PolicyError::PolicyNotFoundError("Policy not found".to_string()));
            },
            Ok(Some(policy)) => policy,
            Err(e) => {
                error!("Database error when checking policy existence: {:?}", e);
                return Err(PolicyError::DatabaseOperationError(e.to_string()));
            },
        };
        let update_model = match PolicyHandler::build_update_model(&request_body, &policy).await {
            Ok(model) => model,
            Err(e) => {
                error!("Failed to build update model: {:?}", e);
                return Err(PolicyError::IncorrectFormatError(e.to_string()));
            },
        };
        let update_model = match PolicyHandler::verify_and_sign_policy(&db, &policy, update_model).await {
            Ok(model) => model,
            Err(PolicyError::PolicySignatureFailure(msg)) => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "message": msg
                })));
            },
            Err(e) => return Err(e),
        };
        match PolicyRepository::update_policy(&db, update_model).await {
            Ok((id, name, version)) => {
                info!("Policy {} updated successfully. Version: {}", id, version);
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "policy":{
                        "id": id,
                        "name": name,
                        "version": version
                    }
                })))
            },
            Err(e) => match e {
                PolicyError::TooManyRequestsError(msg) => Err(PolicyError::TooManyRequestsError(msg)),
                _ => {
                    error!("Failed to update policy: {:?}", e);
                    Err(PolicyError::DatabaseOperationError(e.to_string()))
                }
            },
        }
    }

    /// Deletes one or more policies from the system.
    ///
    /// # Arguments
    /// * `req` - The HTTP request containing headers with user information
    /// * `db` - Database connection wrapped in Arc for thread safety
    /// * `request_body` - JSON payload containing required field:
    ///   - delete_type: Type of deletion to perform ("id", "attester_type", or "all")
    ///   Based on delete_type, additional fields may be required:
    ///   - For "id": ids - Array of policy IDs to delete
    ///   - For "attester_type": attester_type - String specifying the attester type
    ///   - For "all": No additional fields required
    ///
    /// # Returns
    /// * `Ok(HttpResponse)` - Success response with empty body
    /// * `Err(PolicyError)` - Various error types including validation or database errors
    pub async fn delete_policy(
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        request_body: web::Json<Value>,
    ) -> Result<HttpResponse, PolicyError> {
        info!("Handling request to delete policy");
                let json_string = request_body.to_string();
        let req_body: PolicyDeleteRequest = serde_json::from_str(&json_string)
            .map_err(|err| PolicyError::IncorrectFormatError(format!("JSON body error: {}", err)))?;
        req_body.validate().map_err(|e| PolicyError::IncorrectFormatError(e.to_string()))?;
        let user_id = req.headers().get("User-Id").and_then(|h| h.to_str().ok()).unwrap_or("system").to_string();

        let delete_type = request_body["delete_type"]
            .as_str()
            .ok_or_else(|| PolicyError::IncorrectFormatError("delete_type must be a string".to_string()))?;

        let result = match delete_type {
            "id" => {
                let policy_ids: Vec<String> = request_body["ids"]
                    .as_array()
                    .ok_or_else(|| PolicyError::IncorrectFormatError("ids must be an array".to_string()))?
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                PolicyRepository::delete_policies(&db, policy_ids, user_id).await
            },
            "attester_type" => {
                let attester_type = request_body["attester_type"]
                    .as_str()
                    .ok_or_else(|| PolicyError::IncorrectFormatError("attester_type must be a string".to_string()))?
                    .to_string();
                PolicyRepository::delete_policies_by_type(&db, attester_type, user_id).await
            },
            "all" => PolicyRepository::delete_all_policies(&db, user_id).await,
            _ => Err(PolicyError::IncorrectFormatError("Invalid delete_type".to_string())),
        };

        match result {
            Ok(()) => {
                info!("Policies deleted successfully");
                Ok(HttpResponse::Ok().finish())
            },
            Err(e) => {
                error!("Failed to delete policies: {:?}", e);
                Err(e)
            },
        }
    }

    /// Queries policies based on different criteria.
    ///
    /// # Arguments
    /// * `req` - The HTTP request containing headers with user information
    /// * `db` - Database connection wrapped in Arc for thread safety
    /// * `query_params` - Query parameters containing optional query filters:
    ///   - ids: Comma-separated list of policy IDs to query specific policies
    ///   - attester_type: Query policies by attester type
    ///   If no parameters are provided, all policies for the user will be returned
    ///
    /// # Returns
    /// * `Ok(HttpResponse)` - Success response with array of matching policies
    ///   For queries by ID, full policy details are returned
    ///   For other queries, basic policy information is returned
    ///   Results are limited by the user_policy_query_limit configuration
    /// * `Err(PolicyError)` - Various error types including validation or database errors
    pub async fn query_policy(
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        query_params: Query<Value>,
    ) -> Result<HttpResponse, PolicyError> {
        info!("Handling request to query policy");
        let user_id = req.headers().get("User-Id").and_then(|h| h.to_str().ok()).unwrap_or("system").to_string();
        let mut response = serde_json::Map::new();
        let user_policy_query_limit = CONFIG.get_instance().unwrap().attestation_service.policy.query_user_policy_limit as u64;
        let policies_json: Vec<Value>;

        if let Err(e) = ParameterFilter::validate_query_params(&query_params) {
            error!("Invalid query parameters: {}", e);
            return Err(e);
        }

        if query_params.get("ids").is_some() {
            let policies = PolicyHandler::query_policies_by_ids(&db, &query_params, user_id).await?;
            policies_json = policies.iter().map(|p| p.to_full_json()).collect();
            if policies_json.len() > user_policy_query_limit as usize {
                response.insert(
                    "message".to_string(),
                    Value::String(
                        "The queried policy list is larger than the upper limit configured for a single user"
                            .to_string(),
                    ),
                );
                response.insert(
                    "policies".to_string(),
                    Value::Array(policies_json[..user_policy_query_limit as usize].to_vec()),
                );
            } else {
                response.insert("policies".to_string(), Value::Array(policies_json.clone()));
            }
        } else if query_params.get("attester_type").is_some() {
            let policies = PolicyHandler::query_policies_by_type(&db, &query_params, user_id).await?;
            policies_json = policies.iter().map(|p| p.to_base_json()).collect();
            response.insert("policies".to_string(), Value::Array(policies_json.clone()));
        } else {
            let policies = PolicyHandler::get_all_policies(&db, user_id).await?;
            policies_json = policies.iter().map(|p| p.to_base_json()).collect();
            response.insert("policies".to_string(), Value::Array(policies_json.clone()));
        }

        Ok(HttpResponse::Ok().json(response))
    }
}
