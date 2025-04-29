use cert_info::ActiveModel;
use endorserment::entities::cert_revoked_list::Model as CertRevokedListModel;
use endorserment::entities::{cert_info, cert_revoked_list};
use endorserment::repositories::cert_repository::CertRepository;
use endorserment::services::cert_service::DeleteType;
use sea_orm::{ActiveValue, DatabaseBackend, DbErr, MockDatabase, MockExecResult, TransactionTrait};

#[tokio::test]
async fn test_update_cert_info_when_one_row_affected_then_success() {
    // Prepare test data
    let cert_info = ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        name: ActiveValue::Set(Some("new_name".to_string())),
        description: ActiveValue::Set(Some("new_description".to_string())),
        version: ActiveValue::Set(Some(2)),
        ..Default::default()
    };

    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    // Execute update operation
    let result = CertRepository::update_cert_info(
        &db,
        &"test_id".to_string(),
        1,
        cert_info
    ).await;

    // Verify results
    assert!(result.is_ok());
    let update_result = result.unwrap();
    assert_eq!(update_result.rows_affected, 1);
}

#[tokio::test]
async fn test_update_cert_info_when_no_rows_affected_then_success() {
    // Create mock database, simulate no matching record found
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let id = "nonexistent_cert_id".to_string();
    let version = 1;
    let cert_info = cert_info::ActiveModel {
        id: ActiveValue::Set(id.clone()),
        signature: ActiveValue::Set(Some(Vec::from("new_signature".to_string()))),
        key_version: ActiveValue::Set(Some("new_key_version".to_string())),
        ..Default::default()
    };

    let result = CertRepository::update_cert_info_when_signature_update(
        &transaction,
        &id,
        version,
        cert_info
    ).await;

    assert!(result.is_ok());
    let update_result = result.unwrap();
    assert_eq!(update_result.rows_affected, 0);
}

#[tokio::test]
async fn test_update_cert_info_when_db_error_then_error() {
    // Create mock database, simulate database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let id = "test_cert_id".to_string();
    let version = 1;
    let cert_info = cert_info::ActiveModel {
        id: ActiveValue::Set(id.clone()),
        signature: ActiveValue::Set(Some(Vec::from("new_signature".to_string()))),
        key_version: ActiveValue::Set(Some("new_key_version".to_string())),
        ..Default::default()
    };

    let result = CertRepository::update_cert_info_when_signature_update(
        &transaction,
        &id,
        version,
        cert_info
    ).await;

    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(err_msg)) => assert_eq!(err_msg, "Database error"),
        _ => panic!("Expected Custom DbErr"),
    }
}

#[tokio::test]
async fn test_update_cert_info_when_version_mismatch_then_success() {
    // Create mock database, simulate version mismatch
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let id = "test_cert_id".to_string();
    let wrong_version = 999; // Use wrong version number
    let cert_info = cert_info::ActiveModel {
        id: ActiveValue::Set(id.clone()),
        signature: ActiveValue::Set(Some(Vec::from("new_signature".to_string()))),
        key_version: ActiveValue::Set(Some("new_key_version".to_string())),
        ..Default::default()
    };

    let result = CertRepository::update_cert_info_when_signature_update(
        &transaction,
        &id,
        wrong_version,
        cert_info
    ).await;

    assert!(result.is_ok());
    let update_result = result.unwrap();
    assert_eq!(update_result.rows_affected, 0);
}


#[tokio::test]
async fn test_update_cert_info_when_version_conflict_then_success() {
    // Prepare test data
    let cert_info = cert_info::ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        name: ActiveValue::Set(Some("new_name".to_string())),
        version: ActiveValue::Set(Some(2)),
        ..Default::default()
    };

    // Create mock database, return 0 rows affected to indicate version conflict
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    // Execute update operation
    let result = CertRepository::update_cert_info(
        &db,
        &"test_id".to_string(),
        1,
        cert_info
    ).await;

    // Verify results
    assert!(result.is_ok());
    let update_result = result.unwrap();
    assert_eq!(update_result.rows_affected, 0);
}

#[tokio::test]
async fn test_update_cert_info_when_multiple_fields_then_success() {
    // Prepare test data with multiple field updates
    let cert_info = cert_info::ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        name: ActiveValue::Set(Some("new_name".to_string())),
        description: ActiveValue::Set(Some("new_description".to_string())),
        is_default: ActiveValue::Set(Some(true)),
        version: ActiveValue::Set(Some(2)),
        update_time: ActiveValue::Set(Some(1234567890)),
        valid_code: ActiveValue::Set(Some(0)),
        ..Default::default()
    };

    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    // Execute update operation
    let result = CertRepository::update_cert_info(
        &db,
        &"test_id".to_string(),
        1,
        cert_info
    ).await;

    // Verify results
    assert!(result.is_ok());
    let update_result = result.unwrap();
    assert_eq!(update_result.rows_affected, 1);
}


#[tokio::test]
async fn test_find_cert_by_id_exists() {
    // Create mock certificate data
    let mock_cert = cert_info::Model {
        id: "test_cert_id".to_string(),
        name: Some("Test Cert".to_string()),
        cert_type: Some("policy".to_string()),
        cert_info: Some(vec![1, 2, 3]),
        user_id: Some("test_user".to_string()),
        version: Some(1),
        ..Default::default()
    };

    // Set up mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![vec![mock_cert.clone()]])
        .into_connection();

    // Execute test
    let result = CertRepository::find_cert_by_id(&db, &"test_cert_id".to_string()).await;

    // Verify results
    assert!(result.is_ok());
    let cert = result.unwrap();
    assert!(cert.is_some());
    let cert = cert.unwrap();
    assert_eq!(cert.id, "test_cert_id");
    assert_eq!(cert.name, Some("Test Cert".to_string()));
    assert_eq!(cert.cert_type, Some("policy".to_string()));
    assert_eq!(cert.cert_info, Some(vec![1, 2, 3]));
    assert_eq!(cert.user_id, Some("test_user".to_string()));
    assert_eq!(cert.version, Some(1));
}

#[tokio::test]
async fn test_find_cert_by_id_not_exists() {
    // Set up mock database return empty result
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![Vec::<cert_info::Model>::new()])
        .into_connection();

    // Execute test
    let result = CertRepository::find_cert_by_id(&db, &"nonexistent_id".to_string()).await;

    // Verify results
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_find_cert_by_id_when_db_error_then_success() {
    // Set up mock database return error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    // Execute test
    let result = CertRepository::find_cert_by_id(&db, &"test_cert_id".to_string()).await;

    // Verify results
    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(err)) => assert_eq!(err, "Database error"),
        _ => panic!("Expected Custom DbErr"),
    }
}



#[tokio::test]
async fn test_find_parent_cert_by_type_and_user_found() {
    // Prepare test data
    let cert = cert_info::Model {
        id: "test_cert".to_string(),
        user_id: Some("test_user".to_string()),
        cert_type: Some("policy".to_string()),
        owner: Some("test_issuer".to_string()),
        ..Default::default()
    };

    let revoked = cert_revoked_list::Model {
        id: "test_cert".to_string(),
        user_id: Some("test_user".to_string()),
        ..Default::default()
    };

    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![vec![(cert, revoked)]])
        .into_connection();

    // Execute test
    let result = CertRepository::find_parent_cert_by_type_and_user(
        &db,
        "test_user",
        "policy",
        "test_issuer"
    ).await;

    // Verify results
    assert!(result.is_ok());
    let cert_result = result.unwrap();
    assert!(cert_result.is_some());
    let (cert_info, revoked_info) = cert_result.unwrap();
    assert_eq!(cert_info.id, "test_cert");
    assert_eq!(cert_info.user_id.unwrap(), "test_user");
    assert_eq!(cert_info.cert_type.unwrap(), "policy");
    assert_eq!(cert_info.owner.unwrap(), "test_issuer");
    assert!(revoked_info.is_some());
}

#[tokio::test]
async fn test_find_parent_cert_by_type_and_user_when_db_error_then_error() {
    // Create mock database, simulate database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    // Execute test
    let result = CertRepository::find_parent_cert_by_type_and_user(
        &db,
        "test_user",
        "policy",
        "test_issuer"
    ).await;

    // Verify results
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Custom Error: Database error"
    );
}

#[tokio::test]
async fn test_insert_cert_revoked_success() {
    // Create mock database with expected query result
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![vec![
            cert_revoked_list::Model {
                id: "test_id".to_string(),
                serial_num: Some("123456".to_string()),
                user_id: Some("test_user".to_string()),
                cert_revoked_date: Some(1234567890),
                issuer: Some("test_issuer".to_string()),
                signature: Some(vec![1, 2, 3]),
                key_version: Some("v1".to_string()),
                key_id: Some("test_key_id".to_string()),
                valid_code: Some(0),
                cert_revoked_reason: Some("test reason".to_string()),
            }
        ]])
        .into_connection();

    // Prepare test data
    let cert_revoked = endorserment::entities::cert_revoked_list::ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        serial_num: ActiveValue::Set(Option::from("123456".to_string())),
        user_id: ActiveValue::Set(Option::from("test_user".to_string())),
        cert_revoked_date: ActiveValue::Set(Option::from(1234567890)),
        issuer: ActiveValue::Set(Option::from("test_issuer".to_string())),
        signature: ActiveValue::Set(Some(vec![1, 2, 3])),
        key_version: ActiveValue::Set(Option::from("v1".to_string())),
        key_id: ActiveValue::Set(Option::from("test_key_id".to_string())),
        valid_code: ActiveValue::Set(Option::from(0)),
        cert_revoked_reason: ActiveValue::Set(Option::from("test reason".to_string())),
    };

    // Execute test
    let result = CertRepository::insert_cert_revoked(&db, cert_revoked).await;

    // Verify result
    assert!(result.is_ok());
}


#[tokio::test]
async fn test_find_certs_by_type_and_user_when_db_error_then_error() {
    // Create mock database, simulate database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    // Execute test
    let result = CertRepository::find_certs_by_type_and_user(
        &db,
        "user1",
        "policy",
    )
        .await;

    // Verify results
    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(err)) => assert_eq!(err, "Database error"),
        _ => panic!("Expected Custom database error"),
    }
}


#[tokio::test]
async fn test_batch_get_revoke_certs_with_data_success() {
    // Create mock database with expected query result
    let mock_certs = vec![
        cert_revoked_list::Model {
            id: "cert1".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
        cert_revoked_list::Model {
            id: "cert2".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
    ];

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![mock_certs.clone()])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let result = CertRepository::batch_get_revoke_certs(&transaction, 0, 10, "v1").await;

    assert!(result.is_ok());
    let certs = result.unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].id, "cert1");
    assert_eq!(certs[1].id, "cert2");
}

#[tokio::test]
async fn test_batch_get_revoke_certs_pagination_success() {
    // Create mock database with expected query result
    let page_1 = vec![
        cert_revoked_list::Model {
            id: "cert1".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
    ];
    let page_2 = vec![
        cert_revoked_list::Model {
            id: "cert2".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
    ];

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![page_1.clone(), page_2.clone()])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    // Test first page
    let result1 = CertRepository::batch_get_revoke_certs(&transaction, 0, 1, "v1").await;
    assert!(result1.is_ok());
    let certs1 = result1.unwrap();
    assert_eq!(certs1.len(), 1);
    assert_eq!(certs1[0].id, "cert1");

    // Test second page
    let result2 = CertRepository::batch_get_revoke_certs(&transaction, 1, 1, "v1").await;
    assert!(result2.is_ok());
    let certs2 = result2.unwrap();
    assert_eq!(certs2.len(), 1);
    assert_eq!(certs2[0].id, "cert2");
}

#[tokio::test]
async fn test_batch_get_revoke_certs_when_db_error_then_error() {
    // Create mock database, simulate database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let result = CertRepository::batch_get_revoke_certs(&transaction, 0, 10, "v1").await;

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Custom Error: Database error"
    );
}


#[tokio::test]
async fn test_batch_get_all_revoke_certs_total_pages_when_db_error_then_error() {
    // Create mock database, simulate database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let result = CertRepository::batch_get_all_revoke_certs_total_pages(&transaction, 10, "v1").await;

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Custom Error: Database error"
    );
}

#[tokio::test]
async fn test_batch_get_certs_with_data_success() {
    let mock_certs = vec![
        cert_info::Model {
            id: "cert1".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
        cert_info::Model {
            id: "cert2".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
    ];

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![mock_certs.clone()])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let result = CertRepository::batch_get_certs(&transaction, 0, 2, "v1").await;

    assert!(result.is_ok());
    let certs = result.unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].id, "cert1");
    assert_eq!(certs[1].id, "cert2");
}

#[tokio::test]
async fn test_batch_get_certs_pagination_success() {
    let mock_certs_page1 = vec![
        cert_info::Model {
            id: "cert1".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
    ];

    let mock_certs_page2 = vec![
        cert_info::Model {
            id: "cert2".to_string(),
            key_version: Some("v2".to_string()),
            ..Default::default()
        },
    ];

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![mock_certs_page1.clone(), mock_certs_page2.clone()])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    // Test first page
    let result = CertRepository::batch_get_certs(&transaction, 0, 1, "v1").await;
    assert!(result.is_ok());
    let certs = result.unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].id, "cert1");

    // Test second page
    let result = CertRepository::batch_get_certs(&transaction, 1, 1, "v1").await;
    assert!(result.is_ok());
    let certs = result.unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].id, "cert2");
}

#[tokio::test]
async fn test_batch_get_certs_when_db_error_then_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let result = CertRepository::batch_get_certs(&transaction, 0, 10, "v1").await;

    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(err)) => assert_eq!(err, "Database error"),
        _ => panic!("Expected Custom DbErr"),
    }
}

#[tokio::test]
async fn test_batch_get_all_certs_total_pages_when_db_error_then_error() {
    // Create mock database, simulate database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    let result = CertRepository::batch_get_all_certs_total_pages(&transaction, 10, "v1").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DbErr::Custom(_)));
}

#[tokio::test]
async fn test_get_user_revoke_cert_num_when_db_error_then_error() {
    // Create mock database, return error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();

    let result = CertRepository::get_user_revoke_cert_num(&db, "user1").await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Custom Error: Database error"
    );
}

#[tokio::test]
async fn test_verify_name_is_duplicated_when_db_error_then_error() {
    // Set up mock database, return error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();

    let result = CertRepository::verify_name_is_duplicated(
        &db,
        Some("test_cert".to_string()),
        Some("cert1".to_string())
    ).await;

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Custom Error: Database error"
    );
}

#[tokio::test]
async fn test_find_all_when_db_error_then_error() {
    // Create mock database, simulate database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    let result = CertRepository::find_all(&db, &None, &None, "user1").await;

    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(err)) => assert_eq!(err, "Database error"),
        _ => panic!("Expected custom database error"),
    }
}

#[tokio::test]
async fn test_verify_name_when_db_error_then_error() {
    // Create mock database, return error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();

    let result = CertRepository::verify_name_is_duplicated(
        &db,
        Some("test_cert".to_string()),
        Some("existing_id".to_string())
    ).await;

    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(err)) => assert_eq!(err, "Database error"),
        _ => panic!("Expected custom database error"),
    }
}

#[tokio::test]
async fn test_delete_certs_by_id_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    let result = CertRepository::delete_certs(
        &db,
        DeleteType::Id,
        Some(vec!["cert1".to_string(), "cert2".to_string()]),
        None,
        "user1"
    ).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().rows_affected, 2);
}

#[tokio::test]
async fn test_delete_certs_all_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 5,
            },
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            },
        ])
        .into_connection();

    let result = CertRepository::delete_certs(
        &db,
        DeleteType::All,
        None,
        None,
        "user1"
    ).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().rows_affected, 5);
}



#[tokio::test]
async fn test_insert_cert_info_success() {
    // Create test data
    let cert_info = ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        serial_num: ActiveValue::Set(Option::from("123456".to_string())),
        user_id: ActiveValue::Set(Option::from("test_user".to_string())),
        cert_type: ActiveValue::Set(Option::from("policy".to_string())),
        name: ActiveValue::Set(Option::from("test_cert".to_string())),
        issuer: ActiveValue::Set(Option::from("test_issuer".to_string())),
        owner: ActiveValue::Set(Option::from("test_owner".to_string())),
        cert_info: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        is_default: ActiveValue::Set(Option::from(true)),
        description: ActiveValue::Set(Option::from("test description".to_string())),
        version: ActiveValue::Set(Option::from(1)),
        create_time: ActiveValue::Set(Some(1234567890)),
        update_time: ActiveValue::Set(Some(1234567890)),
        signature: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        key_version: ActiveValue::Set(Option::from("v1".to_string())),
        key_id: ActiveValue::Set(Option::from("test_key_id".to_string())), // Modify here
        valid_code: ActiveValue::Set(Option::from(0)),
    };

    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            },
        ])
        .into_connection();

    // Execute test
    let result = CertRepository::insert_cert_info(&db, cert_info, 10).await;

    // Verify results
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);
}

#[tokio::test]
async fn test_insert_cert_info_when_exceed_limit_then_success() {
    let cert_info = ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        serial_num: ActiveValue::Set(Option::from("123456".to_string())),
        user_id: ActiveValue::Set(Option::from("test_user".to_string())),
        cert_type: ActiveValue::Set(Option::from("policy".to_string())),
        name: ActiveValue::Set(Option::from("test_cert".to_string())),
        issuer: ActiveValue::Set(Option::from("test_issuer".to_string())),
        owner: ActiveValue::Set(Option::from("test_owner".to_string())),
        cert_info: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        is_default: ActiveValue::Set(Option::from(true)),
        description: ActiveValue::Set(Option::from("test description".to_string())),
        version: ActiveValue::Set(Option::from(1)),
        create_time: ActiveValue::Set(Some(1234567890)),
        update_time: ActiveValue::Set(Some(1234567890)),
        signature: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        key_version: ActiveValue::Set(Option::from("v1".to_string())),
        key_id: ActiveValue::Set(Option::from("test_key_id".to_string())), // Modify here
        valid_code: ActiveValue::Set(Option::from(0)),
    };

    // Create mock database, set to not insert any row (exceed limit)
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    // Execute test
    let result = CertRepository::insert_cert_info(&db, cert_info, 0).await;

    // Verify results
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_insert_cert_info_when_db_error_then_error() {
    let cert_info = ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        serial_num: ActiveValue::Set(Option::from("123456".to_string())),
        user_id: ActiveValue::Set(Option::from("test_user".to_string())),
        cert_type: ActiveValue::Set(Option::from("policy".to_string())),
        name: ActiveValue::Set(Option::from("test_cert".to_string())),
        issuer: ActiveValue::Set(Option::from("test_issuer".to_string())),
        owner: ActiveValue::Set(Option::from("test_owner".to_string())),
        cert_info: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        is_default: ActiveValue::Set(Option::from(true)),
        description: ActiveValue::Set(Option::from("test description".to_string())),
        version: ActiveValue::Set(Option::from(1)),
        create_time: ActiveValue::Set(Some(1234567890)),
        update_time: ActiveValue::Set(Some(1234567890)),
        signature: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        key_version: ActiveValue::Set(Option::from("v1".to_string())),
        key_id: ActiveValue::Set(Option::from("test_key_id".to_string())), // Modify here
        valid_code: ActiveValue::Set(Option::from(0)),
    };

    // Create mock database, set to return error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();

    // Execute test
    let result = CertRepository::insert_cert_info(&db, cert_info, 10).await;

    // Verify results
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Custom Error: Database error");
}

#[tokio::test]
async fn test_insert_cert_info_duplicate_success() {
    let cert_info = ActiveModel {
        id: ActiveValue::Set("test_id".to_string()),
        serial_num: ActiveValue::Set(Option::from("123456".to_string())),
        user_id: ActiveValue::Set(Option::from("test_user".to_string())),
        cert_type: ActiveValue::Set(Option::from("policy".to_string())),
        name: ActiveValue::Set(Option::from("test_cert".to_string())),
        issuer: ActiveValue::Set(Option::from("test_issuer".to_string())),
        owner: ActiveValue::Set(Option::from("test_owner".to_string())),
        cert_info: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        is_default: ActiveValue::Set(Option::from(true)),
        description: ActiveValue::Set(Option::from("test description".to_string())),
        version: ActiveValue::Set(Option::from(1)),
        create_time: ActiveValue::Set(Some(1234567890)),
        update_time: ActiveValue::Set(Some(1234567890)),
        signature: ActiveValue::Set(Option::from(vec![1, 2, 3])), // Modify here
        key_version: ActiveValue::Set(Option::from("v1".to_string())),
        key_id: ActiveValue::Set(Option::from("test_key_id".to_string())), // Modify here
        valid_code: ActiveValue::Set(Option::from(0)),
    };

    // Create mock database, set to not insert any row (duplicate data)
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            },
        ])
        .into_connection();

    // Execute test
    let result = CertRepository::insert_cert_info(&db, cert_info, 10).await;

    // Verify results
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_update_revoke_cert_info_success() {
    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();

    // Start transaction
    let txn = db.begin().await.unwrap();

    // Prepare test data
    let id = "test_id".to_string();
    let cert_revoked = cert_revoked_list::ActiveModel {
        id: ActiveValue::Set(id.clone()),
        serial_num: ActiveValue::Set(Some("123456".to_string())),
        user_id: ActiveValue::Set(Some("test_user".to_string())),
        cert_revoked_date: ActiveValue::Set(Some(1234567890)),
        issuer: ActiveValue::Set(Some("test_issuer".to_string())),
        signature: ActiveValue::Set(Some(vec![1, 2, 3])),
        key_version: ActiveValue::Set(Some("v1".to_string())),
        key_id: ActiveValue::Set(Some("test_key_id".to_string())),
        valid_code: ActiveValue::Set(Some(0)),
        cert_revoked_reason: ActiveValue::Set(Some("test reason".to_string())),
    };

    // Execute test
    let result = CertRepository::update_revoke_cert_info(&txn, &id, cert_revoked).await;

    // Verify results
    assert!(result.is_ok());
    let update_result = result.unwrap();
    assert_eq!(update_result.rows_affected, 1);
}

#[tokio::test]
async fn test_update_cert_revoked_valid_code_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![vec![
            CertRevokedListModel {
                id: "test_id".to_string(),
                serial_num: Some("123456".to_string()),
                user_id: Some("test_user".to_string()),
                cert_revoked_date: Some(1234567890),
                issuer: Some("test_issuer".to_string()),
                signature: Some(vec![1, 2, 3]),
                key_version: Some("v1".to_string()),
                key_id: Some("test_key_id".to_string()),
                valid_code: Some(1),
                cert_revoked_reason: Some("test reason".to_string()),
            }
        ]])
        .into_connection();

    // Start transaction
    let txn = db.begin().await.unwrap();

    // Execute test
    let id = "test_id".to_string();
    let valid_code = Some(1);
    let result = CertRepository::update_cert_revoked_valid_code(&txn, &id, valid_code).await;

    // Verify results
    assert!(result.is_ok());
    let updated_model = result.unwrap();
    assert_eq!(updated_model.id, "test_id");
    assert_eq!(updated_model.valid_code, Some(1));
}

#[tokio::test]
async fn test_update_cert_revoked_when_valid_code_not_found_then_error() {
    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::RecordNotFound("Record not found".to_string())])
        .into_connection();

    // Start transaction
    let txn = db.begin().await.unwrap();

    // Execute test
    let id = "non_existent_id".to_string();
    let valid_code = Some(1);
    let result = CertRepository::update_cert_revoked_valid_code(&txn, &id, valid_code).await;

    // Verify results
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DbErr::RecordNotFound(_)));
}


#[tokio::test]
async fn test_update_cert_revoked_valid_code_when_db_error_then_error() {
    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    // Start transaction
    let txn = db.begin().await.unwrap();

    // Execute test
    let id = "test_id".to_string();
    let valid_code = Some(1);
    let result = CertRepository::update_cert_revoked_valid_code(&txn, &id, valid_code).await;

    // Verify results
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Custom Error: Database error");
}

#[tokio::test]
async fn test_find_all_without_ids_with_cert_type_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .append_query_results(vec![
            vec![
                cert_info::Model {
                    id: "test_id".to_string(),
                    serial_num: None,
                    user_id: Option::from("test_user".to_string()),
                    cert_type: None,
                    name: Some("test_cert".to_string()),
                    issuer: None,
                    owner: None,
                    cert_info: None,
                    is_default: None,
                    description: None,
                    version: Some(1),
                    create_time: None,
                    update_time: None,
                    signature: None,
                    key_version: None,
                    key_id: None,
                    valid_code: None,
                }
            ]
        ])
        .into_connection();

    let ids = None;
    let cert_type = Some("policy".to_string());
    let user_id = "test_user";

    let result = CertRepository::find_all(&db, &ids, &cert_type, user_id).await;

    assert!(result.is_ok());
    let certs = result.unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].0.id, "test_id");
    assert!(certs[0].1.is_none());
}

#[tokio::test]
async fn test_find_all_without_ids_and_cert_type_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .append_query_results(vec![
            vec![
                cert_info::Model {
                    id: "test_id".to_string(),
                    serial_num: None,
                    user_id: Option::from("test_user".to_string()),
                    cert_type: None,
                    name: Some("test_cert".to_string()),
                    issuer: None,
                    owner: None,
                    cert_info: None,
                    is_default: None,
                    description: None,
                    version: Some(1),
                    create_time: None,
                    update_time: None,
                    signature: None,
                    key_version: None,
                    key_id: None,
                    valid_code: None,
                }
            ]
        ])
        .into_connection();

    let ids = None;
    let cert_type = None;
    let user_id = "test_user";

    let result = CertRepository::find_all(&db, &ids, &cert_type, user_id).await;

    assert!(result.is_ok());
    let certs = result.unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].0.id, "test_id");
    assert!(certs[0].1.is_none());
}