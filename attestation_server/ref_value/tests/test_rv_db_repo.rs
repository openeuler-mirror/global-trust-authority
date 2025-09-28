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

use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Set};
use rv::entities::db_model::rv_db_model::ActiveModel;
use rv::entities::db_model::rv_detail_db_model::Model;
use rv::entities::inner_model::rv_model::RefValueModel;
use rv::entities::request_body::rv_update_req_body::RvUpdateReqBody;
use rv::error::ref_value_error::RefValueError;
use rv::repositories::rv_db_repo::RvDbRepo;

#[tokio::test]
async fn test_add_success() {
    // rv_model
    let rv_model = RefValueModel {
        id: "test_id".to_string(),
        uid: "test_user".to_string(),
        name: "test_name".to_string(),
        description: "test_desc".to_string(),
        attester_type: "TPM".to_string(),
        content: "test_content".to_string(),
        is_default: false,
        signature: vec![1, 2, 3],
        key_version: "1.0".to_string(),
        version: 1,
        valid_code: 0,
    };
    let rv_limit = 100;

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            },
        ])
        .into_connection();

    let result = RvDbRepo::add(&db, &rv_model, rv_limit).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_add_db_error() {
    // rv_model
    let rv_model = RefValueModel {
        id: "test_id".to_string(),
        uid: "test_user".to_string(),
        name: "test_name".to_string(),
        description: "test_desc".to_string(),
        attester_type: "TPM".to_string(),
        content: "test_content".to_string(),
        is_default: false,
        signature: vec![1, 2, 3],
        key_version: "1.0".to_string(),
        version: 1,
        valid_code: 0,
    };
    let rv_limit = 100;

    // Mock database with error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    // test
    let result = RvDbRepo::add(&db, &rv_model, rv_limit).await;

    // Verification result
    assert!(result.is_err());
    match result {
        Err(RefValueError::DbError(_)) => (),
        _ => panic!("Expected DbError"),
    }
}

#[tokio::test]
async fn test_update_error() {
    let user_id = "test_user";
    let id = "test_id";
    let update_rv_body = RvUpdateReqBody {
        id: "test_id".to_string(),
        name: Option::from("updated_name".to_string()),
        description: Option::from("updated_desc".to_string()),
        attester_type: Option::from("TPM".to_string()),
        content: Option::from("updated_content".to_string()),
        is_default: Option::from(false),
    };

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            },
        ])
        .into_connection();

    // test
    let result = RvDbRepo::update(&db, user_id, id, &update_rv_body).await;

    // Verification result
    assert!(result.is_err());
}

#[tokio::test]
async fn test_del_all_success() {
    // user_id
    let user_id = "test_user";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 3,
            },
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    // test
    let result = RvDbRepo::del_all(&db, user_id).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_all_first_delete_error() {
    // user_id
    let user_id = "test_user";

    // Mock database with error on first delete
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    //  test
    let result = RvDbRepo::del_all(&db, user_id).await;

    // Verification result
    assert!(result.is_err());
    match result {
        Err(RefValueError::DbError(_)) => (),
        _ => panic!("Expected DbError"),
    }
}

#[tokio::test]
async fn test_del_by_id_success() {
    // test data
    let user_id = "test_user";
    let ids = vec!["id1".to_string(), "id2".to_string()];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
        ])
        .into_connection();

    //  test
    let result = RvDbRepo::del_by_id(&db, user_id, &ids).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_id_empty_ids() {
    // test data
    let user_id = "test_user";
    let ids: Vec<String> = vec![];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    //  test
    let result = RvDbRepo::del_by_id(&db, user_id, &ids).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_type_success() {
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

    //  test
    let result = RvDbRepo::del_by_type(&db, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_type_not_found() {
    // test data
    let user_id = "test_user";
    let attester_type = "non_existent_type";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    //  test
    let result = RvDbRepo::del_by_type(&db, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_del_by_type_special_chars() {
    // test data 
    let user_id = "test@user";
    let attester_type = "TPM-2.0";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    //  test
    let result = RvDbRepo::del_by_type(&db, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_query_all_empty() {
    // test data
    let user_id = "test_user";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![Vec::<Model>::new()])
        .into_connection();

    //  test
    let result = RvDbRepo::query_all(&db, user_id).await;

    // Verification result
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_query_all_db_error() {
    // test data
    let user_id = "test_user";

    // Mock database with error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    //  test
    let result = RvDbRepo::query_all(&db, user_id).await;

    // Verification result
    assert!(result.is_err());
    match result {
        Err(RefValueError::DbError(_)) => (),
        _ => panic!("Expected DbError"),
    }
}

#[tokio::test]
async fn test_query_all_success() {
    // test data
    let user_id = "test_user";
    let mock_models = vec![
        rv::entities::db_model::rv_db_model::Model {
            id: "1".to_string(),
            uid: user_id.to_string(),
            name: "test1".to_string(),
            description: "desc1".to_string(),
            attester_type: "TPM".to_string(),
            content: "content1".to_string(),
            is_default: false,
            signature: vec![1, 2, 3],
            key_version: "1.0".to_string(),
            version: 1,
            valid_code: 0,
            create_time: 1000,
            update_time: 1000,
        },
        rv::entities::db_model::rv_db_model::Model {
            id: "2".to_string(),
            uid: user_id.to_string(),
            name: "test2".to_string(),
            description: "desc2".to_string(),
            attester_type: "TPM".to_string(),
            content: "content2".to_string(),
            is_default: false,
            signature: vec![4, 5, 6],
            key_version: "1.0".to_string(),
            version: 1,
            valid_code: 0,
            create_time: 2000,
            update_time: 2000,
        },
    ];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![mock_models.clone()])
        .into_connection();

    //  test
    let result = RvDbRepo::query_all(&db, user_id).await;

    // Verification result
    assert!(result.is_ok());
    let models = result.unwrap();
    assert_eq!(models.len(), 2);
    assert_eq!(models[0].id, "1");
    assert_eq!(models[1].id, "2");
}

#[tokio::test]
async fn test_query_all_by_attester_type_empty() {
    // test data
    let user_id = "test_user";
    let attester_type = "non_existent_type";

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![Vec::<Model>::new()])
        .into_connection();

    //  test
    let result = RvDbRepo::query_all_by_attester_type(&db, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_query_all_by_attester_type_success() {
    // test data
    let user_id = "test_user";
    let attester_type = "TPM";
    let mock_models = vec![
        rv::entities::db_model::rv_db_model::Model {
            id: "1".to_string(),
            uid: user_id.to_string(),
            name: "test1".to_string(),
            description: "desc1".to_string(),
            attester_type: "TPM".to_string(),
            content: "content1".to_string(),
            is_default: false,
            signature: vec![1, 2, 3],
            key_version: "1.0".to_string(),
            version: 1,
            valid_code: 0,
            create_time: 1000,
            update_time: 1000,
        }
    ];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![mock_models.clone()])
        .into_connection();

    //  test
    let result = RvDbRepo::query_all_by_attester_type(&db, user_id, attester_type).await;

    // Verification result
    assert!(result.is_ok());
    let models = result.unwrap();
    assert_eq!(models.len(), 1);
}

#[tokio::test]
async fn test_query_all_by_attester_type_db_error() {
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

    //  test
    let result = RvDbRepo::query_all_by_attester_type(&db, user_id, attester_type).await;

    // Verification result
    assert!(result.is_err());
    match result {
        Err(RefValueError::DbError(_)) => (),
        _ => panic!("Expected DbError"),
    }
}

#[tokio::test]
async fn test_query_page_by_attester_type_and_uid_success() {
    // test data
    let attester_type = "TPM";
    let uid = "test_user";
    let page_num = 1;
    let page_size = 10;

    let mock_models = vec![
        rv::entities::db_model::rv_db_model::Model {
            id: "1".to_string(),
            uid: uid.to_string(),
            name: "test1".to_string(),
            description: "desc1".to_string(),
            attester_type: attester_type.to_string(),
            content: "content1".to_string(),
            is_default: false,
            signature: vec![1, 2, 3],
            key_version: "1.0".to_string(),
            version: 1,
            valid_code: 0,
            create_time: 1000,
            update_time: 1000,
        },
        rv::entities::db_model::rv_db_model::Model {
            id: "2".to_string(),
            uid: uid.to_string(),
            name: "test2".to_string(),
            description: "desc2".to_string(),
            attester_type: attester_type.to_string(),
            content: "content2".to_string(),
            is_default: false,
            signature: vec![4, 5, 6],
            key_version: "1.0".to_string(),
            version: 1,
            valid_code: 0,
            create_time: 2000,
            update_time: 2000,
        },
    ];

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![mock_models.clone()])
        .into_connection();

    //  test
    let result = RvDbRepo::query_page_by_attester_type_and_uid(
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
async fn test_query_page_by_attester_type_and_uid_empty() {
    // test data
    let attester_type = "TPM";
    let uid = "test_user";
    let page_num = 1;
    let page_size = 10;

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![Vec::<rv::entities::db_model::rv_db_model::Model>::new()])
        .into_connection();

    //  test
    let result = RvDbRepo::query_page_by_attester_type_and_uid(
        &db,
        attester_type,
        uid,
        page_num,
        page_size,
    ).await;

    // Verification result
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_update_by_id_and_version_no_rows_affected() {
    // test data
    let id = "test_id";
    let cur_version = 1;
    let active_model = ActiveModel {
        valid_code: Set(1),
        ..Default::default()
    };

    // Mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    //  test
    let result = RvDbRepo::update_by_id_and_version(&db, active_model, id, cur_version).await;

    // Verification result
    assert!(result.is_err());
    match result {
        Err(RefValueError::DbError(msg)) => {
            assert!(msg.contains("has been modified"));
        },
        _ => panic!("Expected DbError with modification message"),
    }
}
