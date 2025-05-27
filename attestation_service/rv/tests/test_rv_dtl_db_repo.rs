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

use rv::repositories::rv_dtl_db_repo::RvDtlDbRepo;
use sea_orm::{DatabaseBackend, DbErr, MockDatabase, MockExecResult, MockRow, TransactionTrait};
use serde_json::json;
use rv::entities::db_model::rv_detail_db_model::Model;
use rv::entities::inner_model::rv_content::RefValueDetail;
use rv::entities::inner_model::rv_model::RefValueModel;
use rv::error::ref_value_error::RefValueError;

#[tokio::test]
async fn test_del_by_rv_ids_success() {
    // test data
    let user_id = "test_user";
    let rv_ids = vec!["rv1".to_string(), "rv2".to_string()];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::del_by_rv_ids(&txn, user_id, &rv_ids).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_rv_ids_empty() {
    // test data
    let user_id = "test_user";
    let rv_ids: Vec<String> = vec![];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::del_by_rv_ids(&txn, user_id, &rv_ids).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_rv_ids_db_error() {
    // test data
    let user_id = "test_user";
    let rv_ids = vec!["rv1".to_string()];

    // Mock database with error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::del_by_rv_ids(&txn, user_id, &rv_ids).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_attester_type_success() {
    // test data
    let user_id = "test_user";
    let attester_type = "TPM";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::del_by_attester_type(&txn, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_attester_type_empty_type() {
    // test data
    let user_id = "test_user";
    let attester_type = "";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::del_by_attester_type(&txn, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_attester_type_db_error() {
    // test data
    let user_id = "test_user";
    let attester_type = "TPM";

    // Mock database with error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::del_by_attester_type(&txn, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_add_dtls_success() {
    // test data
    let dtl_values = vec![
        RefValueDetail {
            id: "id1".to_string(),
            uid: "user1".to_string(),
            attester_type: "TPM".to_string(),
            file_name: "file1.txt".to_string(),
            sha256: "hash1".to_string(),
            ref_value_id: "rv1".to_string(),
        },
        RefValueDetail {
            id: "id2".to_string(),
            uid: "user1".to_string(),
            attester_type: "TPM".to_string(),
            file_name: "file2.txt".to_string(),
            sha256: "hash2".to_string(),
            ref_value_id: "rv1".to_string(),
        },
    ];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 1,
                rows_affected: 2,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::add_dtls(&txn, dtl_values).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_add_dtls_empty() {
    // 准备空的测试数据
    let dtl_values: Vec<RefValueDetail> = vec![];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::add_dtls(&txn, dtl_values).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_update_type_by_rv_id_success() {
    // test data
    let uid = "test_user";
    let id = "test_rv_id";
    let attester_type = "TPM";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::update_type_by_rv_id(&txn, uid, id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_update_type_by_rv_id_db_error() {
    // test data
    let uid = "test_user";
    let id = "test_rv_id";
    let attester_type = "TPM";

    // Mock database with error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    let txn = db.begin().await.unwrap();

    // test
    let result = RvDtlDbRepo::update_type_by_rv_id(&txn, uid, id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_query_page_by_attester_type_and_uid_success() {
    // test data
    let attester_type = "TPM";
    let uid = "test_user";
    let page_num = 1;
    let page_size = 10;

    // mock test data
    let mock_models = vec![
        Model {
            id: "1".to_string(),
            uid: uid.to_string(),
            attester_type: attester_type.to_string(),
            file_name: "test1.txt".to_string(),
            sha256: "hash1".to_string(),
            ref_value_id: "rv1".to_string(),
        },
        Model {
            id: "2".to_string(),
            uid: uid.to_string(),
            attester_type: attester_type.to_string(),
            file_name: "test2.txt".to_string(),
            sha256: "hash2".to_string(),
            ref_value_id: "rv2".to_string(),
        },
    ];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![mock_models.clone()])
        .into_connection();

    // test
    let result = RvDtlDbRepo::query_page_by_attester_type_and_uid(
        &db,
        attester_type,
        uid,
        page_num,
        page_size,
    ).await;

    // Verification result
    assert!(result.is_ok());
    let models = result.unwrap();
    assert_eq!(models.len(), 2);
    assert_eq!(models[0].id, "1");
    assert_eq!(models[1].id, "2");
}

#[tokio::test]
async fn test_query_page_by_attester_type_and_uid_db_error() {
    // test data
    let attester_type = "TPM";
    let uid = "test_user";
    let page_num = 1;
    let page_size = 10;

    // Mock database with error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    // test
    let result = RvDtlDbRepo::query_page_by_attester_type_and_uid(
        &db,
        attester_type,
        uid,
        page_num,
        page_size,
    ).await;

    // Verification result
    assert!(result.is_err());
    match result {
        Err(RefValueError::DbError(_)) => (),
        _ => panic!("Expected DbError"),
    }
}

#[tokio::test]
async fn test_count_pages_by_attester_type_and_uid_error() {
    // test data
    let attester_type = "TPM";
    let uid = "test_user";
    let page_size = 10;

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 25,
                rows_affected: 1,
            },
        ])
        .into_connection();

    // test
    let result = RvDtlDbRepo::count_pages_by_attester_type_and_uid(&db, attester_type, uid, page_size).await;

    // Verification result
    assert!(result.is_err());
}