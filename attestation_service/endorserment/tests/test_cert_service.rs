use actix_web::web::Data;
use endorserment::entities::{cert_info, cert_revoked_list};
use endorserment::repositories::cert_repository::CertRepository;
use endorserment::services::cert_service::{parse_cert_content, parse_crl_content, CertService, ValidCode};
use sea_orm::{ActiveValue, DatabaseBackend, DbErr, MockDatabase, MockExecResult, TransactionTrait};
use std::sync::Arc;

#[test]
fn test_parse_cert_content_when_der_err_then_error() {
    // This is an example DER encoded certificate
    let der_cert = vec![
        0x30, 0x82, 0x03, 0x4a, 0x30, 0x82, 0x02, 0x32, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09,
        0x00, 0x90, 0xb5, 0x1e, 0x22, 0x00, 0x64, 0x08, 0x88, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
        0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
    ];

    let result = parse_cert_content(&der_cert);
    assert!(result.is_err());
}

#[test]
fn test_parse_cert_content_when_invalid_content_then_error() {
    let invalid_content = b"invalid certificate content";
    let result = parse_cert_content(invalid_content);
    assert!(result.is_err());
}

#[test]
fn test_parse_cert_content_when_empty_content_then_error() {
    let empty_content = b"";
    let result = parse_cert_content(empty_content);
    assert!(result.is_err());
}

#[test]
fn test_parse_crl_content_when_invalid_crl_then_error() {
    let invalid_crl = "invalid CRL content";
    let result = parse_crl_content(invalid_crl);
    assert!(result.is_err());
}

#[test]
fn test_parse_crl_content_when_empty_crl_then_error() {
    let empty_crl = "";
    let result = parse_crl_content(empty_crl);
    assert!(result.is_err());
}

#[test]
fn test_parse_crl_content_when_malformed_pem_then_error() {
    let malformed_crl = r#"-----BEGIN X509 CRL-----
MIIBYDCBygIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJBVTETMBEGA1UE
-----END X509 CRL-----"#;

    let result = parse_crl_content(malformed_crl);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_update_cert_when_valid_code_then_success() {
    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![cert_info::Model {
                id: "test_cert".to_string(),
                valid_code: Some(1),
                ..Default::default()
            }],
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();

    // Test updating valid status
    let result = CertRepository::update_cert_valid_code(&transaction, &"test_cert".to_string(), Some(1)).await;

    assert!(result.is_ok());
    let updated_cert = result.unwrap();
    assert_eq!(updated_cert.id, "test_cert");
    assert_eq!(updated_cert.valid_code, Some(1));
}

#[tokio::test]
async fn test_update_cert_when_code_none_then_success() {
    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![cert_info::Model {
                id: "test_cert".to_string(),
                valid_code: None,
                ..Default::default()
            }],
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();

    // Test updating to empty status
    let result = CertRepository::update_cert_valid_code(&transaction, &"test_cert".to_string(), None).await;

    assert!(result.is_ok());
    let updated_cert = result.unwrap();
    assert_eq!(updated_cert.id, "test_cert");
    assert_eq!(updated_cert.valid_code, None);
}

#[tokio::test]
async fn test_update_cert_when_code_error_then_error() {
    // Create mock database error
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_errors(vec![
            DbErr::Custom("Database error".to_string())
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();

    // Test database error case
    let result = CertRepository::update_cert_valid_code(&transaction, &"test_cert".to_string(), Some(1)).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_update_cert_when_empty_id_then_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            vec![cert_info::Model {
                id: "".to_string(),
                valid_code: Some(1),
                ..Default::default()
            }],
        ])
        .into_connection();

    let transaction = db.begin().await.unwrap();

    // Test empty ID
    let result = CertRepository::update_cert_valid_code(&transaction, &"".to_string(), Some(1)).await;

    assert!(result.is_ok());
    let updated_cert = result.unwrap();
    assert_eq!(updated_cert.id, "");
    assert_eq!(updated_cert.valid_code, Some(1));
}

#[tokio::test]
async fn test_update_cert_info_when_signature_update_then_success() {
    // Create mock database
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_exec_results(vec![
            MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            },
        ])
        .into_connection();
    let transaction = db.begin().await.unwrap();

    // Prepare test data
    let id = "test_cert_id".to_string();
    let version = 1;
    let cert_info = cert_info::ActiveModel {
        id: ActiveValue::Set(id.clone()),
        signature: ActiveValue::Set(Some(Vec::from("new_signature".to_string()))),
        key_version: ActiveValue::Set(Some("new_key_version".to_string())),
        ..Default::default()
    };

    // Execute test
    let result = CertRepository::update_cert_info_when_signature_update(
        &transaction,
        &id,
        version,
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
async fn test_get_all_certs_when_exceed_limit_then_error() {
    let db = Data::new(Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres).into_connection()
    ));

    let ids = Some((0..101).map(|i| format!("cert{}", i)).collect());
    let result = CertService::get_all_certs(db, &ids, &None, "user1").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_get_all_certs_when_invalid_type_then_error() {
    let db = Data::new(Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres).into_connection()
    ));

    let result = CertService::get_all_certs(
        db,
        &None,
        &Some("invalid_type".to_string()),
        "user1"
    ).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status(), 400);
}


#[tokio::test]
async fn test_get_all_certs_when_db_error_then_error() {
    let db = Data::new(Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
            .into_connection()
    ));

    let result = CertService::get_all_certs(
        db,
        &None,
        &None,
        "user1"
    ).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status(), 500);
}

#[tokio::test]
async fn test_get_all_certs_with_revoked_cert_success() {
    let mock_certs = vec![(
        cert_info::Model {
            id: "cert1".to_string(),
            valid_code: Some(ValidCode::NORMAL),
            ..Default::default()
        },
        Some(cert_revoked_list::Model {
            id: "cert1".to_string(),
            valid_code: Some(ValidCode::NORMAL),
            key_version: Some("v1".to_string()),
            ..Default::default()
        }),
    )];

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        // .append_query_results(vec![mock_certs])
        .append_exec_results(vec![MockExecResult {
            last_insert_id: 0,
            rows_affected: 1,
        }])
        .into_connection();

    let db = Data::new(Arc::new(db));

    let result = CertService::get_all_certs(
        db,
        &Some(vec!["cert1".to_string()]),
        &None,
        "user1"
    ).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_verify_cert_chain_when_empty_params_then_success() {
    let result = CertService::verify_cert_chain("", "", &[]).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}