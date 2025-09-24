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

use sea_orm::DatabaseConnection;

use crate::{entities::policy::Policy, error::policy_error::PolicyError, handler::query_policy_handler::QueryPolicyHandler};

/// Get policies by their IDs
/// 
/// # Arguments
/// * `db` - Database connection
/// * `policy_ids` - List of policy IDs to retrieve
/// 
/// # Returns
/// * `Result<Vec<Policy>, PolicyError>` - Returns a list of policies on success, error on failure
/// 
/// # Error
/// * `PolicyError` - Returns an error if any of the policies are not found
pub async fn get_policy_by_ids(
    db: &DatabaseConnection,
    policy_ids: Vec<String>,
) -> Result<Vec<Policy>, PolicyError> {
    QueryPolicyHandler::get_policies_by_ids(db, policy_ids).await
}

/// Get default policies by attester type
/// 
/// # Arguments
/// * `db` - Database connection
/// * `attester_type` - Challenge plugin type
/// 
/// # Returns
/// * `Result<Vec<Policy>, PolicyError>` - Returns a list of default policies on success, error on failure
/// 
/// # Error
/// * `PolicyError` - Returns an error if any of the policies are not found
pub async fn get_default_policies_by_type(
    db: &DatabaseConnection,
    attester_type: String<>,
    user_id: &str,
) -> Result<Vec<Policy>, PolicyError> {
    QueryPolicyHandler::get_default_policies_by_type(db, attester_type, user_id).await
}