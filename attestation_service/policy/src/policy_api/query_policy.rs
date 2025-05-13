use sea_orm::DatabaseConnection;

use crate::{entities::policy::Policy, policy_error::policy_error::PolicyError, handler::query_policy_handler::QueryPolicyHandler};

/// Get policies by their IDs
/// 
/// # Arguments
/// * `db` - Database connection
/// * `policy_ids` - List of policy IDs to retrieve
/// 
/// # Returns
/// * `Result<Vec<Policy>, PolicyError>` - Returns a list of policies on success, error on failure
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
pub async fn get_default_policies_by_type(
    db: &DatabaseConnection,
    attester_type: String<>,
) -> Result<Vec<Policy>, PolicyError> {
    QueryPolicyHandler::get_default_policies_by_type(db, attester_type).await
}