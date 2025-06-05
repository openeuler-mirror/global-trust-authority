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

use crate::entities::policy_db_model::{ActiveModel, Column, Entity as PolicyEntity, Model};
use crate::entities::signature_policy::SignaturePolicy;
use crate::policy_error::policy_error::PolicyError;
use key_management::key_manager::error::KeyManagerError;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, Set, Statement,
};
use serde_json::Value;
use common_log::info;
use rdb::get_connection;

pub struct PolicyRepository;

impl PolicyRepository {
    /// Gets the version of a policy by its ID.
    ///
    /// # Arguments
    /// * `policy_id` - The ID of the policy to query
    ///
    /// # Returns
    /// * `Result<i32, PolicyError>` - The policy version if found, otherwise an error
    /// * `PolicyNotFoundError` - If the policy with the given ID does not exist
    /// * `PolicyVersionOverflowError` - If the policy version has reached the maximum value
    /// * `DatabaseOperationError` - If there is an error during database operation
    /// 
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database query
    /// * Failed to retrieve policy data
    ///
    /// # Panics
    /// Panics if the database connection cannot be obtained.
    pub async fn get_policy_version(policy_id: String) -> Result<i32, PolicyError> {
        let connect = get_connection().await.unwrap();
        let connection = connect.as_ref();
        let result = PolicyEntity::find()
            .filter(Column::PolicyId.eq(policy_id))
            .column(Column::PolicyVersion)
            .into_model::<Model>()
            .one(connection)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
        // Check if the policy exists
        if result.is_none() {
            return Err(PolicyError::PolicyNotFoundError("Policy not found".to_string()));
        }

        // Extract the policy model from the Option
        let model = result.unwrap();

        // Check if the policy version has reached the maximum value
        if model.policy_version >= i32::MAX {
            return Err(PolicyError::PolicyVersionOverflowError("2147483647".to_string()));
        }

        // Return the policy version as i32
        Ok(model.policy_version)
    }

    /// Adds a new policy to the database, with a check against the user's policy limit.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `policy` - The policy model to be added
    /// * `policy_limit` - Maximum number of policies a user can have
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if successful, otherwise a PolicyError
    /// * `PolicyLimitReached` - If the user has reached their maximum number of policies
    /// * `DatabaseOperationError` - If there is an error during database operation
    /// 
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Policy already exists
    /// * Policy already exists
    pub async fn add_policy(
        db: &DatabaseConnection,
        policy: ActiveModel,
        policy_limit: u64,
    ) -> Result<(), PolicyError> {
        let policy_id = policy.policy_id.unwrap();
        let policy_name = policy.policy_name.unwrap();
        let policy_description = policy.policy_description.unwrap();
        let policy_content = policy.policy_content.unwrap();
        let is_default = policy.is_default.unwrap();
        let policy_version = policy.policy_version.unwrap();
        let create_time = policy.create_time.unwrap();
        let update_time = policy.update_time.unwrap();
        let user_id = policy.user_id.unwrap();
        let attester_type = policy.attester_type.unwrap();
        let signature = policy.signature.unwrap();
        let key_version = policy.key_version.unwrap();
        let product_name = policy.product_name.unwrap();
        let product_type = policy.product_type.unwrap();
        let board_type = policy.board_type.unwrap();

        let sql = Self::generate_add_policy_sql(db);

        let result = db
            .execute(Statement::from_sql_and_values(
                db.get_database_backend(),
                &sql,
                vec![
                    user_id.clone().into(),
                    policy_name.clone().into(),
                    user_id.clone().into(),
                    policy_id.into(),
                    policy_name.into(),
                    policy_description.into(),
                    policy_content.into(),
                    is_default.into(),
                    policy_version.into(),
                    create_time.into(),
                    update_time.into(),
                    user_id.into(),
                    attester_type.into(),
                    signature.into(),
                    0.into(),
                    key_version.into(),
                    product_name.into(),
                    product_type.into(),
                    board_type.into(),
                    policy_limit.into(),
                ],
            ))
            .await
            .map_err(|e| {
                if e.to_string().contains("unique constraint") {
                    PolicyError::PolicyExistError("Policy already exists".to_string())
                } else {
                    PolicyError::DatabaseOperationError(e.to_string())
                }
            })?;
        if result.rows_affected() == 0 {
            return Err(PolicyError::TooManyRequestsError(
                "User has reached the maximum number of policies or policy name is exist, please retry!".to_string(),
            ));
        }

        Ok(())
    }

    /// Updates an existing policy in the database with optimistic concurrency control.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `policy` - The policy model with updated values
    ///
    /// # Returns
    /// * `Result<(String, String, i32), PolicyError>` - Tuple of (policy_id, policy_name, policy_version) if successful
    /// * `TooManyRequestsError` - If the policy has been modified by another request
    /// * `DatabaseOperationError` - If there is an error during database operation
    /// 
    /// # Errors
    /// Returns `PolicyError::TooManyRequestsError` if the policy has been modified by another request.
    /// Returns `PolicyError::DatabaseOperationError` if there is an error during database operation.
    /// Returns `PolicyError::InvalidParameter` if the policy version is at the minimum value, preventing decrement.
    pub async fn update_policy(
        db: &DatabaseConnection,
        policy: ActiveModel,
    ) -> Result<(String, String, i32), PolicyError> {
        let policy_id = policy.policy_id.clone().unwrap();
        let policy_name = policy.policy_name.clone().unwrap();
        let policy_version = policy.policy_version.clone().unwrap();
        let current_version = policy_version - 1;

        let update_result = PolicyEntity::update_many()
            .set(policy)
            .filter(
                Column::PolicyId.eq(policy_id.clone())
                    .and(Column::PolicyVersion.eq(current_version))
            )
            .exec(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        if update_result.rows_affected == 0 {
            return Err(PolicyError::TooManyRequestsError(
                "Policy has been modified by another request, please retry".to_string(),
            ));
        }

        Ok((policy_id, policy_name, policy_version))
    }

    /// Checks if a policy exists based on user ID and policy ID, and validates policy name uniqueness.
    ///
    /// # Arguments
    /// * `headers` - The HTTP request headers containing user ID
    /// * `request_body` - The request body containing policy ID and optionally policy name
    ///
    /// # Returns
    /// * `Result<Option<Model>, PolicyError>` - The policy if found, None if not found
    ///
    /// # Errors
    /// Returns `PolicyError` when:
    /// * `PolicyExistError` - If a policy with the same name already exists for this user
    /// * `DatabaseOperationError` - If there is an error during database operation
    /// * `InvalidParameter` - If the policy ID is missing or invalid in the request body
    pub async fn check_policy_exists(
        headers: &actix_web::http::header::HeaderMap,
        request_body: &Value,
    ) -> Result<Option<Model>, PolicyError> {
        let user_id = headers.get("User-Id").and_then(|h| h.to_str().ok()).unwrap_or("system").to_string();
        let id = request_body["id"].as_str().unwrap().to_string();
        let connect = get_connection().await.unwrap();
        let connection = connect.as_ref();
        info!("start update_policy_check_name");
        if let Some(name) = request_body.get("name").and_then(|n| n.as_str()) {
            if let Some(_) = PolicyEntity::find()
                .filter(
                    Column::UserId
                        .eq(user_id.clone())
                        .and(Column::PolicyName.eq(name))
                        .and(Column::PolicyId.ne(id.clone())),
                )
                .one(connection)
                .await
                .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?
            {
                return Err(PolicyError::PolicyExistError(format!("Policy name '{}' already exists", name)));
            }
        }
        let policy = PolicyEntity::find()
            .filter(Column::UserId.eq(user_id).and(Column::PolicyId.eq(id)))
            .one(connection)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
        Ok(policy)
    }

    /// Checks if a policy exists based on policy ID.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `policy_id` - The policy ID to check
    ///
    /// # Returns
    /// * `Result<Option<Model>, PolicyError>` - The policy if found, None if not found
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database query
    /// * Failed to retrieve policy data
    pub async fn check_policy_exist_use_id(
        db: &DatabaseConnection,
        policy_id: String,
    ) -> Result<Option<Model>, PolicyError> {
        let policy = PolicyEntity::find()
            .filter(Column::PolicyId.eq(policy_id))
            .one(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        Ok(policy)
    }

    /// Checks if a policy exists based on policy name for a specific user.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `user_id` - The ID of the user who owns the policy
    /// * `policy_name` - The policy name to check
    ///
    /// # Returns
    /// * `Result<Option<Model>, PolicyError>` - The policy if found, None if not found
    /// * `DatabaseOperationError` - If there is an error during database operation
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database query
    /// * Failed to retrieve policy data
    pub async fn check_policy_exist_policy_name(
        db: &DatabaseConnection,
        user_id: String,
        policy_name: String,
    ) -> Result<Option<Model>, PolicyError> {
        let policy = PolicyEntity::find()
            .filter(Column::UserId.eq(user_id).and(Column::PolicyName.eq(policy_name)))
            .one(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        Ok(policy)
    }

    /// Deletes multiple policies by their IDs for a specific user.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `policy_ids` - List of policy IDs to delete
    /// * `user_id` - The ID of the user who owns the policies
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if successful
    /// * `DatabaseOperationError` - If there is an error during database operation
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database operation
    pub async fn delete_policies(
        db: &DatabaseConnection,
        policy_ids: Vec<String>,
        user_id: String,
    ) -> Result<(), PolicyError> {
        PolicyEntity::delete_many()
            .filter(Column::PolicyId.is_in(policy_ids).and(Column::UserId.eq(user_id)))
            .exec(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        Ok(())
    }

    /// Deletes all policies of a specific attester type for a user.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `attester_type` - The type of attester whose policies to delete
    /// * `user_id` - The ID of the user who owns the policies
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if successful
    /// * `DatabaseOperationError` - If there is an error during database operation
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database operation
    pub async fn delete_policies_by_type(
        db: &DatabaseConnection,
        attester_type: String,
        user_id: String,
    ) -> Result<(), PolicyError> {
        PolicyEntity::delete_many()
            .filter(
                Column::UserId
                    .eq(user_id)
                    .and(Expr::cust(&format!("JSON_CONTAINS(attester_type, '\"{}\"')", attester_type))),
            )
            .exec(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        Ok(())
    }

    /// Deletes all policies for a specific user.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `user_id` - The ID of the user whose policies to delete
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if successful
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database operation
    pub async fn delete_all_policies(db: &DatabaseConnection, user_id: String) -> Result<(), PolicyError> {
        PolicyEntity::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        Ok(())
    }

    /// Retrieves all default policies for a specific attester type.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `attester_type` - The type of attester to filter policies
    ///
    /// # Returns
    /// * `Result<Vec<SignaturePolicy>, PolicyError>` - List of default policies with valid signatures
    /// * `DatabaseOperationError` - If there is an error during database operation
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database operation
    pub async fn get_default_policies_by_type(
        db: &DatabaseConnection,
        attester_type: String,
    ) -> Result<Vec<SignaturePolicy>, PolicyError> {
        let policy_models = PolicyEntity::find()
            .filter(
                Column::IsDefault
                    .eq(true)
                    .and(Column::ValidCode.eq(0))
                    .and(Expr::cust(&format!("JSON_CONTAINS(attester_type, '\"{}\"')", attester_type))),
            )
            .into_model::<Model>()
            .all(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        let signature_policies: Vec<SignaturePolicy> =
            policy_models.into_iter().map(|model| model.into()).collect::<Vec<_>>();

        Ok(signature_policies)
    }

    /// Retrieves multiple policies by their IDs for a specific user.
    ///
    /// # Arguments
    /// * `db` - The database transaction
    /// * `uuids` - List of policy IDs to retrieve
    /// * `user_id` - The ID of the user who owns the policies
    ///
    /// # Returns
    /// * `Result<Vec<SignaturePolicy>, PolicyError>` - List of policies if successful, otherwise a PolicyError
    pub async fn get_policies_by_ids(
        db: &DatabaseConnection,
        uuids: Vec<String>,
        user_id: String,
    ) -> Result<Vec<SignaturePolicy>, PolicyError> {
        let policy_models = PolicyEntity::find()
            .filter(Column::PolicyId.is_in(uuids).and(Column::UserId.eq(user_id)))
            .into_model::<Model>()
            .all(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        let policies: Vec<SignaturePolicy> =
            policy_models.into_iter().map(|model| SignaturePolicy::from(model)).collect();

        Ok(policies)
    }

    /// Retrieves all policies of a specific attester type for a user.
    ///
    /// # Arguments
    /// * `db` - The database transaction
    /// * `attester_type` - The type of attester to filter policies
    /// * `user_id` - The ID of the user who owns the policies
    ///
    /// # Returns
    /// * `Result<Vec<SignaturePolicy>, PolicyError>` - List of policies if successful, otherwise a PolicyError
    pub async fn get_policies_by_type(
        db: &DatabaseConnection,
        attester_type: String,
        user_id: String,
    ) -> Result<Vec<SignaturePolicy>, PolicyError> {
        let policy_models = PolicyEntity::find()
            .filter(
                Column::UserId
                    .eq(user_id)
                    .and(Expr::cust(&format!("JSON_CONTAINS(attester_type, '\"{}\"')", attester_type))),
            )
            .into_model::<Model>()
            .all(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
        let policies: Vec<SignaturePolicy> =
            policy_models.into_iter().map(|model| SignaturePolicy::from(model)).collect();

        Ok(policies)
    }

    /// Retrieves all policies for a specific user.
    ///
    /// # Arguments
    /// * `db` - The database transaction
    /// * `user_id` - The ID of the user whose policies to retrieve
    ///
    /// # Returns
    /// * `Result<Vec<SignaturePolicy>, PolicyError>` - List of all policies if successful
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database query
    /// * Failed to retrieve policy data
    pub async fn get_all_policies(
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<Vec<SignaturePolicy>, PolicyError> {
        let policy_models = PolicyEntity::find()
            .filter(Column::UserId.eq(user_id))
            .into_model::<Model>()
            .all(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

        let policies: Vec<SignaturePolicy> =
            policy_models.into_iter().map(|model| SignaturePolicy::from(model)).collect();

        Ok(policies)
    }

    /// Marks a policy as corrupted by setting its valid code to 1.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `policy_id` - The UUID of the policy to mark as corrupted
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if successful
    ///
    /// # Errors
    /// Returns `PolicyError` when:
    /// * `DatabaseOperationError` - Failed to execute database operation
    /// * `PolicyNotFoundError` - Policy with the given ID does not exist
    pub async fn set_is_corrupted(db: &DatabaseConnection, policy_id: String) -> Result<(), PolicyError> {
        let policy = PolicyEntity::find_by_id(policy_id)
            .one(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?
            .ok_or_else(|| PolicyError::PolicyNotFoundError("Policy not found".to_string()))?;
        let mut active_model: ActiveModel = policy.into();
        active_model.valid_code = ActiveValue::Set(1);
        active_model.update(db).await.map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
        Ok(())
    }

    /// Marks a policy as corrupted using a database connection instead of a transaction.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `policy_id` - The UUID of the policy to mark as corrupted
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Ok if successful, otherwise a PolicyError
    pub async fn set_is_corrupted_use_connection(
        db: &DatabaseConnection,
        policy_id: String,
    ) -> Result<(), PolicyError> {
        let policy = PolicyEntity::find_by_id(policy_id)
            .one(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?
            .ok_or_else(|| PolicyError::PolicyNotFoundError("Policy not found".to_string()))?;
        let mut active_model: ActiveModel = policy.into();
        active_model.valid_code = ActiveValue::Set(1);
        active_model.update(db).await.map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
        Ok(())
    }

    /// Retrieves non-corrupted policies by their IDs.
    ///
    /// # Arguments
    /// * `db` - The database connection
    /// * `uuids` - List of policy UUIDs to retrieve
    ///
    /// # Returns
    /// * `Result<Vec<SignaturePolicy>, PolicyError>` - List of non-corrupted policies if successful
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database query
    /// * Failed to retrieve policy data
    pub async fn get_correct_policies_by_ids(
        db: &DatabaseConnection,
        policy_ids: Vec<String>,
    ) -> Result<Vec<SignaturePolicy>, PolicyError> {
        let policy_models = PolicyEntity::find()
            .filter(Column::PolicyId.is_in(policy_ids).and(Column::ValidCode.eq(0)))
            .into_model::<Model>()
            .all(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
        let signature_policy = policy_models.into_iter().map(|model| model.into()).collect::<Vec<_>>();
        Ok(signature_policy)
    }

    /// Gets the total count of policies owned by a specific user.
    ///
    /// # Arguments
    /// * `db` - The database transaction
    /// * `user_id` - The ID of the user whose policies to count
    ///
    /// # Returns
    /// * `Result<u64, PolicyError>` - The count of policies if successful
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database query
    /// * Failed to count policy records
    pub async fn get_user_policy_count(db: &DatabaseTransaction, user_id: String) -> Result<u64, PolicyError> {
        PolicyEntity::find()
            .filter(Column::UserId.eq(user_id))
            .count(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))
    }

    /// Gets the total count of policies owned by a specific user.
    ///
    /// # Arguments
    /// * `db` - The database Connection
    /// * `user_id` - The ID of the user whose policies to count
    ///
    /// # Returns
    /// * `Result<u64, PolicyError>` - The count of policies if successful
    ///
    /// # Errors
    /// Returns `PolicyError::DatabaseOperationError` when:
    /// * Failed to execute database query
    /// * Failed to count policy records
    pub async fn get_user_policy_count_with_connection(
        db: &DatabaseConnection,
        user_id: String,
    ) -> Result<u64, PolicyError> {
        PolicyEntity::find()
            .filter(Column::UserId.eq(user_id))
            .count(db)
            .await
            .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))
    }

    /// Retrieves all policies that don't match the specified key version.
    ///
    /// # Arguments
    /// * `db` - The database transaction
    /// * `key_version` - The key version to compare against
    ///
    /// # Returns
    /// * `Result<Vec<SignaturePolicy>, KeyManagerError>` - List of policies with different key versions if successful
    ///
    /// # Errors
    /// Returns `KeyManagerError` when:
    /// * Failed to execute database query
    /// * Failed to retrieve policy data
    pub async fn get_policies_by_key_version(
        db: &DatabaseTransaction,
        key_version: &str,
    ) -> Result<Vec<SignaturePolicy>, KeyManagerError> {
        let result = PolicyEntity::find()
            .filter(Column::KeyVersion.ne(key_version))
            .into_model::<Model>()
            .all(db)
            .await
            .map_err(|e| KeyManagerError::new(format!("Database operation error: {}", e)))?;

        let policies = result.into_iter().map(SignaturePolicy::from).collect();
        Ok(policies)
    }

    /// Updates the signature and key version of a policy.
    ///
    /// # Arguments
    /// * `db` - The database transaction
    /// * `policy_id` - The ID of the policy to update
    /// * `new_version` - The new key version
    /// * `new_signature` - The new signature bytes
    ///
    /// # Returns
    /// * `Result<(), KeyManagerError>` - Ok if successful
    ///
    /// # Errors
    /// Returns `KeyManagerError` when:
    /// * Failed to find policy in database
    /// * Failed to update policy signature
    pub async fn update_policy_signature(
        db: &DatabaseTransaction,
        policy_id: String,
        new_version: &str,
        new_signature: &[u8],
    ) -> Result<(), KeyManagerError> {
        let policy = PolicyEntity::find_by_id(policy_id)
            .one(db)
            .await
            .map_err(|e| KeyManagerError::new(format!("Failed to find policy: {}", e)))?;

        if let Some(model) = policy {
            let mut active_model: ActiveModel = model.into();
            active_model.key_version = Set(new_version.to_string());
            active_model.signature = Set(new_signature.to_vec());

            active_model
                .update(db)
                .await
                .map_err(|e| KeyManagerError::new(format!("Failed to update policy signature: {}", e)))?;
        }

        Ok(())
    }

    /// Updates the corruption status of a policy.
    ///
    /// # Arguments
    /// * `db` - The database transaction
    /// * `policy_id` - The ID of the policy to update
    /// * `valid_code` - The new validity code to set
    ///
    /// # Returns
    /// * `Result<(), KeyManagerError>` - Ok if successful
    ///
    /// # Errors
    /// Returns `KeyManagerError` when:
    /// * Failed to find policy in database
    /// * Failed to update policy corruption status
    pub async fn update_policy_corrupted(
        db: &DatabaseTransaction,
        policy_id: String,
        valid_code: i8,
    ) -> Result<(), KeyManagerError> {
        let policy = PolicyEntity::find_by_id(policy_id)
            .one(db)
            .await
            .map_err(|e| KeyManagerError::new(format!("Failed to find policy: {}", e)))?;

        if let Some(model) = policy {
            let mut active_model: ActiveModel = model.into();
            active_model.valid_code = Set(valid_code);

            active_model
                .update(db)
                .await
                .map_err(|e| KeyManagerError::new(format!("Failed to update policy corrupted status: {}", e)))?;
        }

        Ok(())
    }


    /// Generates the SQL statement for adding a new policy based on the database backend type.
    ///
    /// # Arguments
    /// * `db` - The database connection to determine the backend type
    ///
    /// # Returns
    /// * String - The SQL statement for the specific database backend
    fn generate_add_policy_sql(db: &DatabaseConnection) -> String {
        match db.get_database_backend() {
            DatabaseBackend::MySql => {
                String::from(r#"
                INSERT INTO policy_information (
                    policy_id, policy_name, policy_description, policy_content,
                    is_default, policy_version, create_time, update_time,
                    user_id, attester_type, signature, valid_code, key_version,
                    product_name, product_type, board_type
                )
                WITH policy_checks AS (
                    SELECT 
                        COUNT(*) as policy_count,
                        EXISTS(SELECT 1 FROM policy_information WHERE user_id = ? AND policy_name = ?) as name_exists
                    FROM policy_information 
                    WHERE user_id = ?
                )
                SELECT
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?
                FROM dual
                WHERE (SELECT policy_count FROM policy_checks) < ?
                AND (SELECT name_exists FROM policy_checks) = false
                "#)
            },
            DatabaseBackend::Postgres => {
                String::from(r#"
                WITH policy_checks AS (
                    SELECT 
                        COUNT(*) as policy_count,
                        EXISTS(SELECT 1 FROM policy_information WHERE user_id = ? AND policy_name = ?) as name_exists
                    FROM policy_information 
                    WHERE user_id = ?
                )
                INSERT INTO policy_information (
                    policy_id, policy_name, policy_description, policy_content,
                    is_default, policy_version, create_time, update_time,
                    user_id, attester_type, signature, valid_code, key_version,
                    product_name, product_type, board_type
                )
                SELECT
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?
                WHERE (SELECT policy_count FROM policy_checks) < ?
                AND (SELECT name_exists FROM policy_checks) = false
                "#)
            },
            _ => panic!("Unsupported database backend"),
        }
    }
}
