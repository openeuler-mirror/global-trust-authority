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

use std::sync::Arc;
use actix_web::{test::TestRequest, web, web::Json};
use sea_orm::{Database, DatabaseConnection, TransactionTrait, ConnectionTrait};
use serde_json::json;

use policy::{
    policy_error::policy_error::PolicyError,
    services::policy_service::PolicyService,
    policy_api::get_policy_by_ids,
};

async fn setup_test_db() -> Result<web::Data<Arc<DatabaseConnection>>, PolicyError> {
    let db = Database::connect("sqlite::memory:?mode=memory&cache=shared").await
        .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

    // Create policy_information table
    db.execute(sea_orm::Statement::from_string(
        db.get_database_backend(),
        "
        CREATE TABLE IF NOT EXISTS policy_information (
            policy_id TEXT PRIMARY KEY,
            policy_name TEXT NOT NULL,
            policy_description TEXT NOT NULL,
            policy_content TEXT NOT NULL,
            is_default BOOLEAN NOT NULL,
            policy_version INTEGER NOT NULL,
            create_time DATETIME NOT NULL,
            update_time DATETIME NOT NULL,
            user_id TEXT NOT NULL,
            attester_type TEXT NOT NULL,
            signature BLOB NOT NULL,
            valid_code INTEGER NOT NULL,
            key_version TEXT NOT NULL,
            product_name TEXT NOT NULL,
            product_type TEXT NOT NULL,
            board_type TEXT NOT NULL
        );
    ".to_string())).await.map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

    // Create dual table for SQLite compatibility
    db.execute(sea_orm::Statement::from_string(
        db.get_database_backend(),
        "
        CREATE TABLE IF NOT EXISTS dual (dummy INTEGER);
        INSERT OR IGNORE INTO dual VALUES (1);
    ".to_string())).await.map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;

    Ok(web::Data::new(Arc::new(db)))
}

// Mock the configuration to disable signature requirement for tests
fn mock_config() {
    std::env::set_var("YAML_CONFIG_FILE_PATH", "");
}

#[tokio::test]
async fn test_add_policy_when_request_is_invalid_then_return_error() {
    mock_config();
    let db = setup_test_db().await.unwrap();

    let request = TestRequest::default()
        .insert_header(("User-Id", "test_user"))
        .to_http_request();

    let request_body = Json(json!({
        "name": "test_policy"
    }));

    let result = PolicyService::add_policy(request, db, request_body).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_delete_policy_when_delete_type_is_id_then_return_success() {
    mock_config();
    let db = setup_test_db().await.unwrap();
    let policy_id = "56f8acab-8a57-404b-842e-60dc17f5b3c4";
    insert_test_policy(&db, policy_id).await.unwrap();

    let request = TestRequest::default()
        .insert_header(("User-Id", "test_user"))
        .to_http_request();

    let request_body = Json(json!({
        "delete_type": "id",
        "ids": ["56f8acab-8a57-404b-842e-60dc17f5b3c4"]
    }));

    let result = PolicyService::delete_policy(request, db, request_body).await;
    let response = result.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_delete_policy_when_delete_type_is_all_then_return_success() {
    mock_config();
    let db = setup_test_db().await.unwrap();
    let policy_id = "56f8acab-8a57-404b-842e-60dc17f5b3c4";
    insert_test_policy(&db, policy_id).await.unwrap();

    let request = TestRequest::default()
        .insert_header(("User-Id", "test_user"))
        .to_http_request();

    let request_body = Json(json!({
        "delete_type": "all",
    }));

    let result = PolicyService::delete_policy(request, db, request_body).await;
    let response = result.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_query_policy_when_policy_exists_then_return_policy() {
    mock_config();
    let db = setup_test_db().await.unwrap();
    let policy_id = "56f8acab-8a57-404b-842e-60dc17f5b3c4";
    insert_test_policy(&db, policy_id).await.unwrap();

    let request = TestRequest::default()
        .insert_header(("User-Id", "test_user"))
        .to_http_request();

    let query_params = web::Query(json!({
        "ids": policy_id
    }));

    let result = PolicyService::query_policy(request, db, query_params).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body();
    let body_bytes = actix_web::body::to_bytes(body).await.unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let policies = body_json.get("policies").unwrap().as_array().unwrap();
    let first_policy = &policies[0];
    let id = first_policy.get("id").unwrap().as_str().unwrap();
    assert_eq!(id, policy_id);
}

#[tokio::test]
async fn test_get_policy_by_ids_when_policy_not_exists_then_return_empty() {
    mock_config();
    let db = setup_test_db().await.unwrap();
    let policy_id = "56f8acab-8a57-404b-842e-60dc17f5b3c4";
    insert_test_policy(&db, policy_id).await.unwrap();
    let policy_id_list = vec!["56f8acab-8a57-404b-842e-60dc17f5b3c4".to_string()];
    let policies = get_policy_by_ids(&db, policy_id_list).await.unwrap();
    assert_eq!(policies.len(), 0);
}

async fn insert_test_policy(db: &DatabaseConnection, policy_id: &str) -> Result<(), PolicyError> {
    let insert_tx = db.begin().await
        .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
    insert_tx.execute(sea_orm::Statement::from_string(
        db.get_database_backend(),
        format!("INSERT INTO policy_information (
                policy_id, policy_name, policy_description, policy_content,
                is_default, policy_version, create_time, update_time,
                user_id, attester_type, signature, valid_code,
                key_version, product_name, product_type, board_type
            ) VALUES (
                '{}', 'test_policy', 'test description', 'dGVzdA==',
                false, 1, '2024-01-01 00:00:00', '2024-01-01 00:00:00',
                'test_user', '[\"TPM\",\"IMA\"]', X'0000', 0,
                'v1.0', 'test_product', 'test_type', 'test_board'
            )", policy_id)
    )).await.map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
    insert_tx.commit().await
        .map_err(|e| PolicyError::DatabaseOperationError(e.to_string()))?;
    Ok(())
}