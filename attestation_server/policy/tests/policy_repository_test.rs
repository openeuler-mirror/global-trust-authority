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

use std::fs;
use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use policy::entities::policy_db_model::{ActiveModel, Model};
use policy::repositories::policy_repository::PolicyRepository;
use sea_orm::{ActiveValue, DatabaseBackend, MockDatabase, MockExecResult, TransactionTrait};
use serde_json::json;
use key_management::key_manager::error::KeyManagerError;
use policy::handler::query_policy_handler::QueryPolicyHandler;
use policy::error::policy_error::PolicyError;

fn create_test_policy() -> ActiveModel {
    ActiveModel {
        policy_id: ActiveValue::Set("test_id".to_string()),
        policy_name: ActiveValue::Set("test_name".to_string()),
        policy_description: ActiveValue::Set("test_desc".to_string()),
        policy_content: ActiveValue::Set("test_content".to_string()),
        is_default: ActiveValue::Set(false),
        policy_version: ActiveValue::Set(1),
        create_time: ActiveValue::Set(123),
        update_time: ActiveValue::Set(456),
        user_id: ActiveValue::Set("test_user".to_string()),
        attester_type:  ActiveValue::Set(serde_json::Value::String("tpm_boot".to_string())),
        signature: ActiveValue::Set(vec![]),
        valid_code: ActiveValue::Set(0),
        key_version: ActiveValue::Set("v1".to_string()),
        product_name: ActiveValue::Set("test_product".to_string()),
        product_type: ActiveValue::Set("test_product_type".to_string()),
        board_type: ActiveValue::Set("test_board".to_string()),
    }
}

#[tokio::test]
async fn test_add_policy_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            },
        ])
        .into_connection();

    let policy = create_test_policy();
    let result = PolicyRepository::add_policy(&db, policy, 10).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_add_policy_db_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_errors(vec![
            sea_orm::DbErr::Custom("database error".to_string()),
        ])
        .into_connection();

    let policy = create_test_policy();
    let result = PolicyRepository::add_policy(&db, policy, 10).await;
    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

#[tokio::test]
async fn test_update_policy_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            },
        ])
        .into_connection();

    let policy = create_test_policy();
    let result = PolicyRepository::update_policy(&db, policy).await;

    assert!(result.is_ok());
    let (policy_id, policy_name, version) = result.unwrap();
    assert_eq!(policy_id, "test_id");
    assert_eq!(policy_name, "test_name");
    assert_eq!(version, 1);
}

#[tokio::test]
async fn test_update_policy_concurrent_modification() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let policy = create_test_policy();
    let result = PolicyRepository::update_policy(&db, policy).await;

    assert!(matches!(result, Err(PolicyError::TooManyRequestsError(_))));
}

fn setup() {
    let env_content = r#"
DB_TYPE=postgres
POSTGRESQL_DATABASE_URL=postgres://postgres:postgres@localhost:5432/test_db
    "#;
    fs::write(".env.dev", env_content).unwrap();
    std::env::set_var("POSTGRESQL_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/test_db");
}

fn teardown() {
    let _ = fs::remove_file(".env.dev");
    std::env::remove_var("POSTGRESQL_DATABASE_URL");
}

#[tokio::test]
async fn test_delete_policies_success() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
        ])
        .into_connection();

    let policy_ids = vec!["policy1".to_string(), "policy2".to_string()];
    let user_id = "test_user".to_string();

    let result = PolicyRepository::delete_policies(&db, policy_ids, user_id).await;
    assert!(result.is_ok());

    teardown();
}

#[tokio::test]
async fn test_delete_policies_empty_list() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let policy_ids = vec![];
    let user_id = "test_user".to_string();

    let result = PolicyRepository::delete_policies(&db, policy_ids, user_id).await;
    assert!(result.is_ok());

    teardown();
}


#[tokio::test]
async fn test_delete_policies_by_type_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
        ])
        .into_connection();

    let attester_type = "test_type".to_string();
    let user_id = "test_user".to_string();

    let result = PolicyRepository::delete_policies_by_type(&db, attester_type, user_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_policies_by_type_no_records() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let attester_type = "non_existent_type".to_string();
    let user_id = "test_user".to_string();

    let result = PolicyRepository::delete_policies_by_type(&db, attester_type, user_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_all_policies_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 5,
            },
        ])
        .into_connection();

    let user_id = "test_user".to_string();

    let result = PolicyRepository::delete_all_policies(&db, user_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_all_policies_db_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let user_id = "test_user".to_string();

    let result = PolicyRepository::delete_all_policies(&db, user_id).await;
    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

fn create_test_model(id: &str) -> Model {
    Model {
        policy_id: id.to_string(),
        policy_name: format!("test_name_{}", id),
        policy_description: "test_desc".to_string(),
        policy_content: "test_content".to_string(),
        is_default: true,
        policy_version: 1,
        create_time: 123,
        update_time: 456,
        user_id: "system".to_string(),
        attester_type: serde_json::Value::String("tpm_boot".to_string()),
        signature: vec![],
        valid_code: 0,
        key_version: "v1".to_string(),
        product_name: "test_product".to_string(),
        product_type: "test_product_type".to_string(),
        board_type: "test_board".to_string(),
    }
}

#[tokio::test]
async fn test_get_default_policies_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![
                create_test_model("1"),
                create_test_model("2"),
            ],
        ])
        .into_connection();

    let attester_type = "test_type".to_string();
    let result = PolicyRepository::get_default_policies_by_type(&db, attester_type).await;

    assert!(result.is_ok());
    let policies = result.unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].policy_id, "1");
    assert_eq!(policies[1].policy_id, "2");
}

#[tokio::test]
async fn test_get_default_policies_db_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let attester_type = "test_type".to_string();
    let result = PolicyRepository::get_default_policies_by_type(&db, attester_type).await;

    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

#[tokio::test]
async fn test_get_policies_by_ids_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![
                create_test_model("1"),
                create_test_model("2"),
            ],
        ])
        .into_connection();

    let uuids = vec!["1".to_string(), "2".to_string()];
    let user_id = "test_user".to_string();

    let result = PolicyRepository::get_policies_by_ids(&db, uuids, user_id).await;

    assert!(result.is_ok());
    let policies = result.unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].policy_id, "1");
    assert_eq!(policies[1].policy_id, "2");
}

#[tokio::test]
async fn test_get_policies_by_type_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![
                create_test_model("1"),
                create_test_model("2"),
            ],
        ])
        .into_connection();

    let attester_type = "test_type".to_string();
    let user_id = "test_user".to_string();

    let result = PolicyRepository::get_policies_by_type(&db, attester_type, user_id).await;

    assert!(result.is_ok());
    let policies = result.unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].policy_id, "1");
    assert_eq!(policies[1].policy_id, "2");
}


#[tokio::test]
async fn test_get_all_policies_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![
                create_test_model("1"),
                create_test_model("2"),
                create_test_model("3"),
            ],
        ])
        .into_connection();

    let user_id = "test_user".to_string();
    let result = PolicyRepository::get_all_policies(&db, user_id).await;

    assert!(result.is_ok());
    let policies = result.unwrap();
    assert_eq!(policies.len(), 3);
    assert_eq!(policies[0].policy_id, "1");
    assert_eq!(policies[1].policy_id, "2");
    assert_eq!(policies[2].policy_id, "3");
}

#[tokio::test]
async fn test_get_all_policies_db_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let user_id = "test_user".to_string();
    let result = PolicyRepository::get_all_policies(&db, user_id).await;

    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

#[tokio::test]
async fn test_set_is_corrupted_find_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let result = PolicyRepository::set_is_corrupted(&db, "test_id".to_string()).await;
    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

#[tokio::test]
async fn test_set_is_corrupted_update_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![create_test_model("test_id")],
        ])
        .append_exec_errors(vec![
            sea_orm::DbErr::Custom("Update error".to_string()),
        ])
        .into_connection();

    let result = PolicyRepository::set_is_corrupted(&db, "test_id".to_string()).await;
    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

#[tokio::test]
async fn test_set_is_corrupted_use_connection_find_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let result = PolicyRepository::set_is_corrupted_use_connection(&db, "test_id".to_string()).await;
    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

#[tokio::test]
async fn test_set_is_corrupted_use_connection_update_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![create_test_model("test_id")],
        ])
        .append_exec_errors(vec![
            sea_orm::DbErr::Custom("Update error".to_string()),
        ])
        .into_connection();

    let result = PolicyRepository::set_is_corrupted_use_connection(&db, "test_id".to_string()).await;
    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));
}

#[tokio::test]
async fn test_get_correct_policies_success() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![
                create_test_model("1"),
                create_test_model("2"),
            ],
        ])
        .into_connection();

    let policy_ids = vec!["1".to_string(), "2".to_string()];
    let result = PolicyRepository::get_correct_policies_by_ids(&db, policy_ids).await;

    assert!(result.is_ok());
    let policies = result.unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].policy_id, "1");
    assert_eq!(policies[1].policy_id, "2");

    teardown();
}

#[tokio::test]
async fn test_get_correct_policies_db_error() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let policy_ids = vec!["1".to_string()];
    let result = PolicyRepository::get_correct_policies_by_ids(&db, policy_ids).await;

    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));

    teardown();
}

#[tokio::test]
async fn test_get_user_policy_count_db_error() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();
    let result = PolicyRepository::get_user_policy_count(&transaction, "test_user".to_string()).await;

    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));

    teardown();
}

#[tokio::test]
async fn test_get_user_policy_count_with_connection_db_error() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let result = PolicyRepository::get_user_policy_count_with_connection(&db, "test_user".to_string()).await;

    assert!(matches!(result, Err(PolicyError::DatabaseOperationError(_))));

    teardown();
}

fn create_test_model_key(id: &str, key_version: &str) -> Model {
    Model {
        policy_id: id.to_string(),
        policy_name: format!("test_name_{}", id),
        policy_description: "test_desc".to_string(),
        policy_content: "test_content".to_string(),
        is_default: true,
        policy_version: 1,
        create_time: 123,
        update_time: 456,
        user_id: "system".to_string(),
        attester_type: serde_json::Value::String("tpm_boot".to_string()),
        signature: vec![],
        valid_code: 0,
        key_version: key_version.to_string(),
        product_name: "test_product".to_string(),
        product_type: "test_product_type".to_string(),
        board_type: "test_board".to_string(),
    }
}

#[tokio::test]
async fn test_get_policies_by_key_version_success() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![
                create_test_model_key("1", "v2"),
                create_test_model_key("2", "v2"),
            ],
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();
    let result = PolicyRepository::get_policies_by_key_version(&transaction, "v1").await;

    assert!(result.is_ok());
    let policies = result.unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].policy_id, "1");
    assert_eq!(policies[1].policy_id, "2");

    teardown();
}

#[tokio::test]
async fn test_update_policy_signature_find_error() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();
    let result = PolicyRepository::update_policy_signature(
        &transaction,
        "test_id".to_string(),
        "v2",
        &[4, 5, 6],
    ).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyManagerError { .. }));

    teardown();
}

#[tokio::test]
async fn test_update_policy_corrupted_find_error() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();
    let result = PolicyRepository::update_policy_corrupted(
        &transaction,
        "test_id".to_string(),
        1,
    ).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyManagerError { .. }));

    teardown();
}

#[tokio::test]
async fn test_update_policy_signature_success() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![create_test_model("test_id")],
            vec![create_test_model("test_id")],
        ])
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();
    let result = PolicyRepository::update_policy_signature(
        &transaction,
        "test_id".to_string(),
        "v2",
        &[4, 5, 6],
    ).await;

    if let Err(ref e) = result {
        println!("Error: {:?}", e);
    }
    assert!(result.is_ok(), "Expected Ok result, got {:?}", result);

    teardown();
}

#[tokio::test]
async fn test_update_policy_corrupted_success() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![create_test_model("test_id")],
            vec![create_test_model("test_id")],
        ])
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();
    let result = PolicyRepository::update_policy_corrupted(
        &transaction,
        "test_id".to_string(),
        1,
    ).await;

    if let Err(ref e) = result {
        println!("Error: {:?}", e);
    }
    assert!(result.is_ok(), "Expected Ok result, got {:?}", result);

    teardown();
}

#[tokio::test]
async fn test_check_policy_exist_use_id_success() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![create_test_model("test_id")],
        ])
        .into_connection();

    let result = PolicyRepository::check_policy_exist_use_id(&db, "test_id".to_string()).await;

    assert!(result.is_ok());
    let policy = result.unwrap();
    assert!(policy.is_some());
    assert_eq!(policy.unwrap().policy_id, "test_id");

    teardown();
}


#[tokio::test]
async fn test_check_policy_exist_use_id_db_error() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let result = PolicyRepository::check_policy_exist_use_id(&db, "test_id".to_string()).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PolicyError::DatabaseOperationError(_)));

    teardown();
}

fn create_test_model_with_user_id(id: &str, name: &str, user_id: &str) -> Model {
    Model {
        policy_id: id.to_string(),
        policy_name: name.to_string(),
        policy_description: "test_desc".to_string(),
        policy_content: "test_content".to_string(),
        is_default: true,
        policy_version: 1,
        create_time: 123,
        update_time: 456,
        user_id: user_id.to_string(),
        attester_type: serde_json::Value::String("tpm_boot".to_string()),
        signature: vec![],
        valid_code: 0,
        key_version: "v1".to_string(),
        product_name: "test_product".to_string(),
        product_type: "test_product_type".to_string(),
        board_type: "test_board".to_string(),
    }
}

#[tokio::test]
async fn test_check_policy_exist_policy_name_success() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![create_test_model_with_user_id("test_id", "test_policy", "test_user")],
        ])
        .into_connection();

    let result = PolicyRepository::check_policy_exist_policy_name(
        &db,
        "test_user".to_string(),
        "test_policy".to_string(),
    ).await;

    assert!(result.is_ok());
    let policy = result.unwrap();
    assert!(policy.is_some());
    let policy = policy.unwrap();
    assert_eq!(policy.policy_name, "test_policy");
    assert_eq!(policy.user_id, "test_user");

    teardown();
}


#[tokio::test]
async fn test_check_policy_exist_policy_name_db_error() {
    setup();

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            sea_orm::DbErr::Custom("Database error".to_string()),
        ])
        .into_connection();

    let result = PolicyRepository::check_policy_exist_policy_name(
        &db,
        "test_user".to_string(),
        "test_policy".to_string(),
    ).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PolicyError::DatabaseOperationError(_)));

    teardown();
}