use crate::entities::cert_error::CertVerifyError;
use crate::entities::{cert_info, cert_revoked_list};
use crate::repositories::cert_repository::CertRepository;
use actix_web::web::Data;
use actix_web::HttpResponse;
use chrono::NaiveDateTime;
use config_manager::types::CONFIG;
use futures::stream::{self, StreamExt};
use common_log::{debug, error, info};
use key_management::api::{impls::DefaultCryptoImpl, CryptoOperations};
use openssl::asn1::Asn1TimeRef;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::sign::Verifier;
use openssl::x509::{ReasonCode, X509Crl, X509};
use rdb::get_connection;
use sea_orm::{ActiveValue, DatabaseConnection, DatabaseTransaction, DbErr, TransactionTrait};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[derive(Deserialize, Debug)]
pub struct QueryInfo {
    pub ids: Option<String>,
    pub cert_type: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub enum DeleteType {
    #[serde(rename = "id")]
    Id,
    #[serde(rename = "type")]
    Type,
    #[serde(rename = "all")]
    All,
}
#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    pub delete_type: DeleteType,
    pub ids: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub cert_type: Option<String>,
}

#[derive(Debug, Validate, Deserialize, Serialize)]
pub struct AddCertRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    #[validate(length(max = 512))]
    pub description: Option<String>,
    #[serde(rename = "type")]
    #[validate(length(min = 1), custom(function = "validate_cert_type"))]
    pub cert_type: Vec<String>,
    pub content: Option<String>,
    pub is_default: Option<bool>,
    #[validate(length(min = 1))]
    pub cert_revoked_list: Option<Vec<String>>,
}

#[derive(Debug, Validate, Deserialize)]
pub struct UpdateCertRequest {
    #[validate(length(min = 1, max = 32))]
    pub id: String,
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    #[validate(length(max = 512))]
    pub description: Option<String>,
    #[serde(rename = "type")]
    #[validate(length(min = 1), custom(function = "validate_cert_type_by_update"))]
    pub cert_type: Option<Vec<String>>,
    pub is_default: Option<bool>,
}

#[derive(Serialize)]
pub struct QueryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub certs: Vec<CertRespInfo>,
}

#[derive(Default, Serialize)]
pub struct CertRespInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_type: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_revoked_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_revoked_reason: Option<String>,
}

#[derive(Serialize)]
pub struct DeleteResponse {
    pub message: String,
}

#[derive(Default, Serialize)]
pub struct AddCertResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertRespInfo>,
}

fn validate_cert_type(cert_type: &Vec<String>) -> Result<(), ValidationError> {
    if cert_type.is_empty() {
        return Err(ValidationError::new("cert_type_empty"));
    }

    for item in cert_type {
        if item.is_empty() || item.len() > 255 {
            return Err(ValidationError::new("invalid_cert_type_length"));
        }
        match item.as_ref() {
            "refvalue" | "policy" | "tpm_boot" | "tpm_ima" | "crl" => {},
            _ => return Err(ValidationError::new("invalid_cert_type")),
        }
    }
    Ok(())
}

fn validate_cert_type_by_update(cert_type: &Vec<String>) -> Result<(), ValidationError> {
    if cert_type.is_empty() {
        return Err(ValidationError::new("cert_type_empty"));
    }

    for item in cert_type {
        if item.is_empty() || item.len() > 255 {
            return Err(ValidationError::new("invalid_cert_type_length"));
        }
        match item.as_ref() {
            "refvalue" | "policy" | "tpm_boot" | "tpm_ima" => {},
            _ => return Err(ValidationError::new("invalid_cert_type")),
        }
    }
    Ok(())
}

/// Analyze certificate content
pub fn parse_cert_content(content: &[u8]) -> Result<X509, ErrorStack> {
    X509::from_pem(content)
}

/// Analyze certificate revocation list
pub fn parse_crl_content(crl_content: &str) -> Result<X509Crl, ErrorStack> {
    X509Crl::from_pem(crl_content.as_bytes())
}

pub fn asn1_time_to_timestamp(asn1_time: &Asn1TimeRef) -> Result<i64, Box<dyn std::error::Error>> {
    // Convert Asn1Time to a string
    let time_str = asn1_time.to_string();

    // Parse the time string as chrono:: NaiveDATE
    let naive_time = NaiveDateTime::parse_from_str(&time_str, "%b %e %H:%M:%S %Y GMT")?;

    // Convert to Unix timestamp
    Ok(naive_time.and_utc().timestamp())
}

/// Generate certificate ID
fn generate_cert_id(serial_num: &str, issuer: &str, user_id: &str) -> String {
    // Combine fields into a string
    let combined = format!("{}-{}-{}", serial_num, issuer, user_id);

    // Generate UUID using UUID v5
    let namespace = Uuid::NAMESPACE_OID; // Using OID namespace
    Uuid::new_v5(&namespace, combined.as_bytes()).to_string().replace("-", "")
}

fn get_cert_serial_number(cert: &X509) -> String {
    let serial_bn = cert.serial_number().to_bn().map_err(|_| return "".to_string()).unwrap();
    hex::encode(serial_bn.to_vec())
}

fn get_cert_issuer_name(cert: &X509) -> String {
    let map = cert
        .issuer_name()
        .entries()
        .into_iter()
        .map(|e| (e.object().to_string(), e.data().as_utf8().map(|x| x.to_string()).unwrap_or("".to_string())))
        .collect::<BTreeMap<String, String>>();
    serde_json::to_string(&map).unwrap_or("".to_string())
}

fn get_cert_subject_name(cert: &X509) -> String {
    let map = cert
        .subject_name()
        .entries()
        .into_iter()
        .map(|e| (e.object().to_string(), e.data().as_utf8().map(|x| x.to_string()).unwrap_or("".to_string())))
        .collect::<BTreeMap<String, String>>();
    serde_json::to_string(&map).unwrap_or("".to_string())
}

fn get_crl_issuer_name(crl: &X509Crl) -> String {
    let map = crl
        .issuer_name()
        .entries()
        .into_iter()
        .map(|e| (e.object().to_string(), e.data().as_utf8().map(|x| x.to_string()).unwrap_or("".to_string())))
        .collect::<BTreeMap<String, String>>();
    serde_json::to_string(&map).unwrap_or("".to_string())
}

pub struct ValidCode;

impl ValidCode {
    // NORMAL
    pub const NORMAL: i32 = 0;
    // VERIFICATION_FAILURE
    const VERIFICATION_FAILURE: i32 = 1;
    // REVOKE
    const REVOKE: i32 = 2;
}

pub(crate) struct CertificateType;

impl CertificateType {
    pub(crate) const REFVALUE: &'static str = "refvalue";
    pub(crate) const POLICY: &'static str = "policy";
    pub(crate) const TPM_BOOT: &'static str = "tpm_boot";
    pub(crate) const TPM_IMA: &'static str = "tpm_ima";
    pub(crate) const CRL: &'static str = "crl";
}

pub struct CertService;

impl CertService {
    pub(crate) const MAX_NUMBER_OF_QUERIES: usize = 100;

    pub async fn get_all_certs(
        db: Data<Arc<DatabaseConnection>>,
        ids: &Option<Vec<String>>,
        cert_type: &Option<String>,
        user_id: &str,
    ) -> actix_web::Result<HttpResponse> {
        info!("Handling request to get all certs");
        // Check if there are more than 100 IDs
        if let Some(ids) = &ids {
            if ids.len() > CertService::MAX_NUMBER_OF_QUERIES {
                error!("IDs exceed maximum limit of 100");
                return Ok(HttpResponse::BadRequest().body("IDs exceed maximum limit of 100".to_string()));
            }
        }
        // Verify the type field
        let valid_types =
            [CertificateType::REFVALUE, CertificateType::POLICY, CertificateType::TPM_BOOT, CertificateType::TPM_IMA];
        if let Some(cert_type) = &cert_type {
            if !valid_types.contains(&cert_type.as_str()) {
                error!("Invalid certificate type");
                return Ok(HttpResponse::BadRequest().body("Invalid certificate type".to_string()));
            }
        }

        match CertRepository::find_all(&db, ids, &cert_type, user_id).await {
            Ok(mut certs) => {
                info!("Successfully retrieved certs");
                let tx = match db.begin().await {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("Failed to get database transaction: {}", e);
                        return Ok(HttpResponse::InternalServerError().body(e.to_string()));
                    },
                };
                // Query single/multiple certificate files (Ids query), verify signatures, check if certificates have expired or been revoked,
                // verify if signature information is valid, mark valid_code, and refresh the database if valid_code changes
                if ids.is_some() {
                    for (cert, cert_revoked) in &mut certs {
                        if let Some(cert_revoked_model) = cert_revoked {
                            if !Self::verify_revoke_cert_complete(&tx, cert_revoked_model).await {
                                cert_revoked_model.valid_code = Some(ValidCode::VERIFICATION_FAILURE);
                            }
                            // Update certificate information to revoked status
                            if !cert.valid_code.eq(&Some(ValidCode::REVOKE)) {
                                match CertRepository::update_cert_valid_code(&tx, &cert.id, Some(ValidCode::REVOKE))
                                    .await
                                {
                                    Ok(_) => debug!("Successfully updated cert"),
                                    Err(e) => error!("Failed to update cert: {}", e),
                                }
                                cert.valid_code = Some(ValidCode::REVOKE);
                            }
                        } else {
                            if !Self::verify_cert_complete(&tx, cert).await {
                                cert.valid_code = Some(ValidCode::VERIFICATION_FAILURE);
                            } else {
                                // Verify if the certificate has expired
                                let timestamp = chrono::Utc::now().timestamp();
                                if let Some(cert_content) = cert.cert_info.clone() {
                                    match parse_cert_content(&String::from_utf8_lossy(&cert_content).as_bytes()) {
                                        Ok(cert_x509) => {
                                            if let Ok(expiration_time) = asn1_time_to_timestamp(cert_x509.not_after()) {
                                                if expiration_time < timestamp
                                                    && cert.valid_code.eq(&Some(ValidCode::NORMAL))
                                                {
                                                    match CertRepository::update_cert_valid_code(
                                                        &tx,
                                                        &cert.id,
                                                        Some(ValidCode::REVOKE),
                                                    )
                                                    .await
                                                    {
                                                        Ok(_) => {
                                                            debug!("Successfully updated cert")
                                                        },
                                                        Err(e) => {
                                                            error!("Failed to update cert: {}", e)
                                                        },
                                                    }
                                                    cert.valid_code = Some(ValidCode::REVOKE);
                                                }
                                            } else {
                                                error!("Failed to obtain the certificate expiration time.");
                                            }
                                        },
                                        Err(e) => error!("Failed to parse cert content: {}", e),
                                    }
                                }
                            }
                        }
                    }
                }
                if let Err(e) = tx.commit().await {
                    error!("Failed to commit database transaction: {}", e);
                    return Ok(HttpResponse::InternalServerError().body(e.to_string()));
                }
                Ok(HttpResponse::Ok().json(CertService::convert_to_query_response(certs)))
            },
            Err(e) => {
                error!("Failed to retrieve certs: {:?}", e);
                Ok(HttpResponse::InternalServerError().body(e.to_string()))
            },
        }
    }

    pub fn convert_to_query_response(
        certs: Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>,
    ) -> QueryResponse {
        QueryResponse {
            message: None,
            certs: certs
                .into_iter()
                .map(|(cert_info, cert_revoked)| CertRespInfo {
                    cert_id: Some(cert_info.id),
                    cert_name: cert_info.name,
                    description: cert_info.description,
                    content: cert_info.cert_info.map(|u| String::from_utf8_lossy(&u).to_string()),
                    cert_type: if let Some(cert_type) = cert_info.cert_type {
                        Some(
                            cert_type.as_array().unwrap().iter().filter_map(|v| v.as_str().map(String::from)).collect(),
                        )
                    } else {
                        None
                    },
                    is_default: cert_info.is_default,
                    version: cert_info.version,
                    create_time: cert_info.create_time,
                    update_time: cert_info.update_time,
                    valid_code: cert_info.valid_code,
                    cert_revoked_date: cert_revoked.as_ref().and_then(|r| r.cert_revoked_date),
                    cert_revoked_reason: cert_revoked.as_ref().and_then(|r| r.cert_revoked_reason.clone()),
                })
                .collect(),
        }
    }

    pub async fn delete_certs(
        db: Data<Arc<DatabaseConnection>>,
        delete_request: DeleteRequest,
        user_id: &str,
    ) -> actix_web::Result<HttpResponse> {
        let delete_type = delete_request.delete_type.clone();
        let ids = delete_request.ids.clone();
        let cert_type = delete_request.cert_type.clone();

        match CertRepository::delete_certs(&db, delete_type, ids, cert_type, user_id).await {
            Ok(_) => Ok(HttpResponse::Ok().json(DeleteResponse { message: "success".to_string() })),
            Err(e) => {
                error!("Failed to delete certs: {:?}", e);
                Ok(HttpResponse::BadRequest().body(e.to_string()))
            },
        }
    }

    /// Verify request and add certificate
    pub async fn add_cert(
        db: Data<Arc<DatabaseConnection>>,
        request: AddCertRequest,
        user_id: &str,
    ) -> actix_web::Result<HttpResponse> {
        if let Err(e) = request.validate() {
            error!("Request body is invalidate: {:?}", e);
            return Ok(HttpResponse::BadRequest().body(e.to_string()));
        }
        // Verify required fields based on type
        if request.cert_type.contains(&CertificateType::CRL.to_string()) {
            if request.cert_type.len() > 1 {
                error!("When a revoked certificate is passed in, the type can only be crl");
                return Ok(HttpResponse::BadRequest()
                    .body("When a revoked certificate is passed in, the type can only be crl".to_string()));
            }
            if request.cert_revoked_list.is_none() {
                error!("Cert revoked list is required for CRL type");
                return Ok(HttpResponse::BadRequest().body("Cert revoked list is required for CRL type".to_string()));
            }
        } else {
            if request.name.is_none() || request.content.is_none() {
                error!("Name and content are required for this type");
                return Ok(HttpResponse::BadRequest().body("Name and content are required for this type".to_string()));
            }
        }
        // Processing certificate types
        if !request.cert_type.contains(&CertificateType::CRL.to_string()) {
            // Analyze certificate content
            let cert_content = request.content.clone().unwrap();
            return match parse_cert_content(&cert_content.as_bytes()) {
                Ok(cert) => {
                    if !CertService::verify_cert(&cert) {
                        error!("The imported certificate is invalid.");
                        return Ok(HttpResponse::BadRequest().body("The imported certificate is invalid.".to_string()));
                    }
                    // Obtain certificate serial number and issuer
                    let serial_num = get_cert_serial_number(&cert);
                    let issuer = get_cert_issuer_name(&cert);
                    let owner = get_cert_subject_name(&cert);
                    // Generate certificate ID
                    let cert_id = generate_cert_id(&serial_num, &issuer, &user_id);
                    let timestamp_millis = chrono::Utc::now().timestamp_millis();
                    // Sign using key management
                    let cert_model_sig = cert_info::Model {
                        id: cert_id.clone(),
                        serial_num: Some(serial_num.clone()),
                        user_id: Some(user_id.to_string()),
                        cert_type: Some(json!(request.cert_type.clone())),
                        name: request.name.clone(),
                        issuer: Some(issuer.clone()),
                        owner: Some(owner.clone()),
                        cert_info: Some(cert_content.clone().into_bytes()),
                        is_default: request.is_default,
                        description: request.description.clone(),
                        version: Some(1),
                        create_time: Some(timestamp_millis),
                        update_time: Some(timestamp_millis),
                        ..Default::default()
                    };
                    let (signature, key_version) = CertService::get_signature(&cert_model_sig).await;
                    // Build cert_info::ActiveModel
                    let cert_info = cert_info::ActiveModel {
                        id: ActiveValue::Set(cert_id.clone()),
                        serial_num: ActiveValue::Set(Some(serial_num)),
                        user_id: ActiveValue::Set(Some(user_id.to_string())),
                        cert_type: ActiveValue::Set(Some(json!(request.cert_type.clone()))),
                        name: ActiveValue::Set(request.name.clone()),
                        issuer: ActiveValue::Set(Some(issuer)),
                        owner: ActiveValue::Set(Some(owner)),
                        cert_info: ActiveValue::Set(Some(cert_content.into_bytes())),
                        is_default: ActiveValue::Set(request.is_default),
                        description: ActiveValue::Set(request.description.clone()),
                        version: ActiveValue::Set(Some(1)),
                        create_time: ActiveValue::Set(Some(timestamp_millis)),
                        update_time: ActiveValue::Set(Some(timestamp_millis)),
                        signature: ActiveValue::Set(signature),
                        key_version: ActiveValue::Set(key_version),
                        valid_code: ActiveValue::Set(Some(ValidCode::NORMAL)),
                        ..Default::default()
                    };

                    // Insert certificate information
                    match CertRepository::insert_cert_info(
                        &db,
                        cert_info,
                        CONFIG.get_instance().unwrap().attestation_service.cert.single_user_cert_limit,
                    )
                    .await
                    {
                        Ok(count) => {
                            if count == 0 {
                                error!(
                                    "User has reached the maximum number of cert or cert name or cert is exist, please retry!"
                                );
                                return Ok(HttpResponse::BadRequest().body(
                                    "User has reached the maximum number of cert or cert name or cert is exist, please retry!"
                                        .to_string(),
                                ));
                            }
                            Ok(HttpResponse::Ok().json(AddCertResponse {
                                cert: Some(CertRespInfo {
                                    cert_id: Some(cert_id),
                                    cert_name: request.name.clone(),
                                    version: Some(1),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }))
                        },
                        Err(e) => {
                            error!("Failed to insert cert info: {:?}", e);
                            Ok(HttpResponse::InternalServerError().body(e.to_string()))
                        },
                    }
                },
                Err(e) => {
                    error!("Failed to parse certificate content: {:?}", e);
                    Ok(HttpResponse::BadRequest().body(e.to_string()))
                },
            };
        } else {
            // Process certificate revocation list
            let crl_list = request.cert_revoked_list.clone().unwrap();
            let mut cert_revoked_list = Vec::new();
            for crl_content in crl_list {
                // Analyze certificate revocation list
                let crl = match parse_crl_content(&crl_content) {
                    Ok(crl) => crl,
                    Err(e) => {
                        error!("Failed to parse CRL content: {:?}", e);
                        return Ok(HttpResponse::BadRequest().body(e.to_string()));
                    },
                };
                let issuer = get_crl_issuer_name(&crl);
                if crl.get_revoked().is_none() {
                    error!("Failed to get CRL revoked");
                    return Ok(HttpResponse::BadRequest().body("Failed to get CRL revoked".to_string()));
                }
                for revoked in crl.get_revoked().unwrap() {
                    // Obtain certificate serial number and issuer
                    let serial_bn = revoked.serial_number().to_bn().map_err(|_| return "".to_string()).unwrap();
                    let serial_num = hex::encode(serial_bn.to_vec());
                    // Obtain revocation time
                    let revocation_timestamp = match asn1_time_to_timestamp(revoked.revocation_date()) {
                        Ok(revocation_timestamp) => revocation_timestamp,
                        Err(e) => {
                            error!("Failed to parse CRL revocation date: {:?}", e);
                            return Ok(
                                HttpResponse::BadRequest().body("Failed to parse CRL revocation date".to_string())
                            );
                        },
                    };
                    // Obtain the reason for revocation
                    let reason_code = match revoked.extension::<ReasonCode>() {
                        Ok(reason) => match reason {
                            Some(reason) => reason.1.get_i64().unwrap_or(0),
                            None => {
                                error!("this user's revoke certs has exceeded the online limit");
                                return Ok(
                                    HttpResponse::BadRequest().body("CRL revocation reason code is empty".to_string())
                                );
                            },
                        },
                        Err(e) => {
                            error!("Failed to parse CRL revocation reason code: {:?}", e);
                            return Ok(HttpResponse::BadRequest()
                                .body("Failed to parse CRL revocation reason code".to_string()));
                        },
                    };
                    // Generate certificate ID
                    let cert_id = generate_cert_id(&serial_num, &issuer, &user_id);
                    // Sign using key management
                    let cert_revoked_model_sig = cert_revoked_list::Model {
                        id: cert_id.clone(),
                        issuer: Some(issuer.clone()),
                        serial_num: Some(serial_num.clone()),
                        user_id: Some(user_id.to_string()),
                        cert_revoked_date: Some(revocation_timestamp),
                        cert_revoked_reason: Some(reason_code.to_string()),
                        ..Default::default()
                    };
                    let (signature, key_version) = CertService::get_signature(&cert_revoked_model_sig).await;
                    // Build cert_revoked_list::ActiveModel
                    let cert_revoked = cert_revoked_list::ActiveModel {
                        id: ActiveValue::Set(cert_id),
                        issuer: ActiveValue::Set(Some(issuer.clone())),
                        serial_num: ActiveValue::Set(Some(serial_num)),
                        user_id: ActiveValue::Set(Some(user_id.to_string())),
                        cert_revoked_date: ActiveValue::Set(Some(revocation_timestamp)),
                        cert_revoked_reason: ActiveValue::Set(Some(reason_code.to_string())),
                        signature: ActiveValue::Set(signature),
                        key_version: ActiveValue::Set(key_version),
                        valid_code: ActiveValue::Set(Some(ValidCode::NORMAL)),
                        ..Default::default()
                    };
                    cert_revoked_list.push(cert_revoked);
                }
                // Insert certificate revocation information
                match CertRepository::get_user_revoke_cert_num(&db, &user_id).await {
                    Ok(count) => {
                        if count + cert_revoked_list.len() as u64
                            > CONFIG.get_instance().unwrap().attestation_service.cert.single_user_cert_limit {
                            error!("this user's revoke certs has exceeded the online limit");
                            return Ok(HttpResponse::BadRequest()
                                .body("this user's revoke certs has exceeded the online limit".to_string()));
                        }
                    },
                    Err(e) => {
                        error!("Failed to get revoke cert count: {:?}", e);
                        return Ok(HttpResponse::InternalServerError().body(e.to_string()));
                    },
                }
                let tx = match db.begin().await {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("Failed to get database transaction: {}", e);
                        return Ok(HttpResponse::InternalServerError().body(e.to_string()));
                    },
                };
                for cert_revoked in cert_revoked_list.clone() {
                    if let Err(e) = CertRepository::insert_cert_revoked(&tx, cert_revoked).await {
                        error!("Failed to insert cert revoked: {:?}", e);
                        if let Err(e) = tx.rollback().await {
                            error!("Failed to rollback database transaction: {}", e);
                        }
                        return Ok(HttpResponse::InternalServerError().body(e.to_string()));
                    }
                }
                if let Err(e) = tx.commit().await {
                    error!("Failed to commit database transaction: {}", e);
                    return Ok(HttpResponse::InternalServerError().body(e.to_string()));
                }
            }
        }

        // Return successful response
        Ok(HttpResponse::Ok().json(AddCertResponse { message: Some("success".to_string()), ..Default::default() }))
    }

    /// Verify requests and update certificates
    pub async fn update_cert(
        db: Data<Arc<DatabaseConnection>>,
        request: UpdateCertRequest,
        user_id: String,
    ) -> actix_web::Result<HttpResponse> {
        if let Err(e) = request.validate() {
            error!("Request body is invalidate: {:?}", e);
            return Ok(HttpResponse::BadRequest().body(e.to_string()));
        }
        if request.name.is_some() {
            match CertRepository::verify_name_is_duplicated(&db, request.name.clone(), Some(request.id.clone())).await {
                Ok(is_exist) => {
                    if is_exist {
                        error!("Name is duplicated");
                        return Ok(HttpResponse::BadRequest().body("Name is duplicated".to_string()));
                    }
                },
                Err(e) => {
                    error!("Failed to verify name is duplicated: {:?}", e);
                    return Ok(HttpResponse::InternalServerError().body(e.to_string()));
                },
            }
        }
        match CertRepository::find_cert_by_id(&db, &request.id).await {
            Ok(cert_info_opt) => match cert_info_opt {
                Some(cert_info_model) => {
                    if !cert_info_model.user_id.clone().unwrap_or("".to_string()).eq(&user_id) {
                        error!("No certificate update permission");
                        return Ok(HttpResponse::BadRequest().body("No certificate update permission".to_string()));
                    }
                    let mut cert_model_sig = cert_info::Model {
                        id: cert_info_model.id.clone(),
                        serial_num: cert_info_model.serial_num.clone(),
                        user_id: cert_info_model.user_id.clone(),
                        cert_type: cert_info_model.cert_type.clone(),
                        name: cert_info_model.name.clone(),
                        issuer: cert_info_model.issuer.clone(),
                        owner: cert_info_model.owner.clone(),
                        cert_info: cert_info_model.cert_info.clone(),
                        is_default: cert_info_model.is_default.clone(),
                        description: cert_info_model.description.clone(),
                        version: cert_info_model.version.clone(),
                        create_time: cert_info_model.create_time.clone(),
                        update_time: cert_info_model.update_time.clone(),
                        ..Default::default()
                    };
                    // Analyze certificate content
                    let timestamp_millis = chrono::Utc::now().timestamp_millis();
                    // Build cert_info::ActiveModel
                    let mut cert_info: cert_info::ActiveModel = cert_info_model.clone().into();
                    if let Some(name) = request.name.clone() {
                        cert_model_sig.name = Some(name.clone());
                        cert_info.name = ActiveValue::Set(Some(name));
                    }
                    if let Some(description) = request.description.clone() {
                        cert_model_sig.description = Some(description.clone());
                        cert_info.description = ActiveValue::Set(Some(description));
                    }
                    if let Some(cert_type) = request.cert_type.clone() {
                        cert_model_sig.cert_type = Some(json!(cert_type.clone()));
                        cert_info.cert_type = ActiveValue::Set(Some(json!(cert_type)));
                    }
                    if let Some(is_default) = request.is_default.clone() {
                        cert_model_sig.is_default = Some(is_default);
                        cert_info.is_default = ActiveValue::Set(Some(is_default));
                    }
                    cert_model_sig.version = Some(cert_info_model.version.clone().unwrap_or(1) + 1);
                    cert_info.version =
                        ActiveValue::Set(Some(cert_info_model.version.clone().unwrap_or(1) + 1));
                    cert_model_sig.update_time = Some(timestamp_millis);
                    cert_info.update_time = ActiveValue::Set(Some(timestamp_millis));

                    // Sign using key management
                    let (signature, key_version) = CertService::get_signature(&cert_model_sig).await;
                    cert_info.signature = ActiveValue::Set(signature);
                    cert_info.key_version = ActiveValue::Set(key_version);
                    match CertRepository::update_cert_info(
                        &db,
                        &request.id,
                        cert_info_model.version.clone().unwrap_or(1),
                        cert_info,
                    )
                    .await
                    {
                        Ok(res) => {
                            if res.rows_affected == 1 {
                                // Return successful response
                                Ok(HttpResponse::Ok().json(AddCertResponse {
                                    cert: Some(CertRespInfo {
                                        cert_id: Some(request.id.clone()),
                                        cert_name: request.name.clone(),
                                        version: Some(cert_info_model.version.clone().unwrap_or(1) + 1),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }))
                            } else {
                                error!("Certificate has been modified by another request, please retry");
                                Ok(HttpResponse::BadRequest()
                                    .body("Certificate has been modified by another request, please retry".to_string()))
                            }
                        },
                        Err(e) => {
                            error!("Certificate update failure {}", e);
                            Ok(HttpResponse::InternalServerError().body("Occur database error".to_string()))
                        },
                    }
                },
                None => {
                    error!("No corresponding certificate found");
                    Ok(HttpResponse::BadRequest().body("No corresponding certificate found"))
                },
            },
            Err(e) => {
                error!("No corresponding certificate found {}", e);
                Ok(HttpResponse::BadRequest().body("Occur database error".to_string()))
            },
        }
    }

    fn verify_cert_time(cert: &X509) -> bool {
        let timestamp = chrono::Utc::now().timestamp();
        if let Ok(expiration_time) = asn1_time_to_timestamp(cert.not_after()) {
            return expiration_time > timestamp;
        }
        false
    }

    fn get_cert_digest(cert: &X509) -> Option<MessageDigest> {
        // Obtain signature algorithm
        let sig_alg = cert.signature_algorithm().object();
        // Judging Abstract Algorithm Based on NID
        match sig_alg.nid() {
            Nid::ECDSA_WITH_SHA256 | Nid::SHA256WITHRSAENCRYPTION => Some(MessageDigest::sha256()),
            Nid::ECDSA_WITH_SHA384 | Nid::SHA384WITHRSAENCRYPTION => Some(MessageDigest::sha384()),
            Nid::ECDSA_WITH_SHA512 | Nid::SHA512WITHRSAENCRYPTION => Some(MessageDigest::sha512()),
            _ => {
                if sig_alg.to_string().eq("SM2-with-SM3") {
                    Some(MessageDigest::sm3())
                } else {
                    None
                }
            },
        }
    }

    pub fn verify_cert(cert: &X509) -> bool {
        if !Self::verify_cert_time(cert) {
            return false;
        }

        let digest = Self::get_cert_digest(cert);
        if digest.is_none() {
            return false;
        }
        // Check if certificate signature algorithm is valid
        cert.public_key()
            .map(|pk| match pk.id() {
                openssl::pkey::Id::RSA => match pk.bits() {
                    2048 | 3072 | 4096 => {
                        debug!("RSA size: {:?}", pk.bits());
                        true
                    },
                    _ => false,
                },
                openssl::pkey::Id::EC => pk
                    .ec_key()
                    .map(|ec_key| {
                        ec_key
                            .group()
                            .curve_name()
                            .map(|curve_name| match curve_name {
                                Nid::X9_62_PRIME256V1 => true,
                                _ => false,
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false),
                _ => digest.unwrap() == MessageDigest::sm3(),
            })
            .unwrap_or(false)
    }

    fn get_crypto_operations() -> impl CryptoOperations {
        DefaultCryptoImpl {}
    }

    pub async fn get_cert_signature(cert: &cert_info::Model) -> (Option<Vec<u8>>, Option<String>) {
        let mut cert_sig = cert.clone();
        cert_sig.signature = None;
        cert_sig.key_version = None;
        cert_sig.key_id = None;
        cert_sig.valid_code = None;
        CertService::get_signature(&cert_sig).await
    }

    pub async fn get_revoke_cert_signature(
        cert_revoked_model: &cert_revoked_list::Model,
    ) -> (Option<Vec<u8>>, Option<String>) {
        let mut cert_sig = cert_revoked_model.clone();
        cert_sig.signature = None;
        cert_sig.key_version = None;
        cert_sig.key_id = None;
        cert_sig.valid_code = None;
        CertService::get_signature(&cert_sig).await
    }

    async fn get_signature(info: &impl Serialize) -> (Option<Vec<u8>>, Option<String>) {
        let crypto_operations = CertService::get_crypto_operations();
        if !crypto_operations.is_require_sign().await.unwrap_or(false) {
            return (None, None);
        }
        let data = serde_json::to_string(info).unwrap_or("".to_string());
        debug!("get_signature:{}", data);
        match crypto_operations.sign(&data.into_bytes(), "FSK").await {
            Ok(res) => (Some(res.signature), Some(res.key_version)),
            Err(_) => (None, None),
        }
    }

    async fn verify_signature(
        info: &impl Serialize,
        signature_opt: Option<Vec<u8>>,
        key_version_opt: Option<String>,
    ) -> bool {
        let crypto_operations = CertService::get_crypto_operations();
        if let (Some(signature), Some(key_version)) = (signature_opt, key_version_opt) {
            let data = serde_json::to_string(info).unwrap_or("".to_string());
            debug!("verify_signature:{}", data);
            crypto_operations
                .verify("FSK", Some(key_version.as_str()), data.into_bytes(), signature)
                .await
                .unwrap_or_else(|_| false)
        } else {
            !crypto_operations.is_require_sign().await.unwrap_or(false)
        }
    }

    pub async fn verify_cert_complete(db: &DatabaseTransaction, cert: &cert_info::Model) -> bool {
        let mut cert_sig = cert.clone();
        cert_sig.signature = None;
        cert_sig.key_version = None;
        cert_sig.key_id = None;
        cert_sig.valid_code = None;
        let is_complete = Self::verify_signature(&cert_sig, cert.signature.clone(), cert.key_version.clone()).await;
        if !is_complete && cert.valid_code.eq(&Some(ValidCode::NORMAL)) {
            match CertRepository::update_cert_valid_code(&db, &cert.id, Some(ValidCode::VERIFICATION_FAILURE)).await {
                Ok(_) => debug!("Successfully updated cert"),
                Err(e) => error!("Failed to update cert: {}", e),
            }
        }
        is_complete
    }

    pub async fn verify_revoke_cert_complete(
        db: &DatabaseTransaction,
        cert_revoked_model: &cert_revoked_list::Model,
    ) -> bool {
        let mut cert_sig = cert_revoked_model.clone();
        cert_sig.signature = None;
        cert_sig.key_version = None;
        cert_sig.key_id = None;
        cert_sig.valid_code = None;
        let is_complete = Self::verify_signature(
            &cert_sig,
            cert_revoked_model.signature.clone(),
            cert_revoked_model.key_version.clone(),
        )
        .await;
        if !is_complete && cert_revoked_model.valid_code.eq(&Some(ValidCode::NORMAL)) {
            match CertRepository::update_cert_revoked_valid_code(
                &db,
                &cert_revoked_model.id,
                Some(ValidCode::VERIFICATION_FAILURE),
            )
            .await
            {
                Ok(_) => debug!("Successfully updated cert revoked"),
                Err(e) => error!("Failed to update cert revoked: {}", e),
            }
        }
        is_complete
    }

    async fn filter_is_not_complete_cert(
        db: &DatabaseTransaction,
        certs: Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>,
    ) -> Vec<cert_info::Model> {
        stream::iter(certs.into_iter())
            .filter_map(|(cert, revoke_cert)| async move {
                if revoke_cert.is_some() {
                    let revoke_is_valid = Self::verify_revoke_cert_complete(db, &revoke_cert.unwrap()).await;
                    if revoke_is_valid {
                        if cert.valid_code.eq(&Some(ValidCode::NORMAL)) {
                            match CertRepository::update_cert_valid_code(&db, &cert.id, Some(ValidCode::REVOKE)).await {
                                Ok(_) => debug!("Successfully updated cert revoked"),
                                Err(e) => error!("Failed to update cert revoked: {}", e),
                            }
                        }
                        return None;
                    }
                }
                let cert_is_valid = Self::verify_cert_complete(db, &cert).await;
                if !cert_is_valid {
                    return None;
                }
                Some(cert)
            })
            .collect::<Vec<_>>()
            .await
    }

    pub async fn verify_by_cert(
        cert_type: &str,
        user_id: &str,
        signature: &[u8],
        alg: MessageDigest,
        data: &[u8],
    ) -> Result<bool, CertVerifyError> {
        if cert_type.is_empty() && user_id.is_empty() {
            error!("The cert_type or user_id is empty");
            return Ok(false);
        }
        info!("Begin verifying certificate signature, user_id: {}, cert_type: {}", user_id, cert_type);
        let db = get_connection().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            CertVerifyError::DbError(e.to_string())
        })?;
        let db = db.as_ref();
        let cert_data = CertRepository::find_certs_by_type_and_user(db, user_id, cert_type).await.map_err(|e| {
            error!("Failed to query certificate by type and user: {:?}", e);
            CertVerifyError::DbError(e.to_string())
        })?;
        if cert_data.is_empty() {
            error!("The certificate queried is empty");
            return Ok(false);
        }
        let tx = db.begin().await.map_err(|e| {
            error!("Failed to get database transaction: {}", e);
            CertVerifyError::DbError(e.to_string())
        })?;
        let certs: Vec<cert_info::Model> = Self::filter_is_not_complete_cert(&tx, cert_data).await;
        tx.commit().await.map_err(|e| {
            error!("Failed to commit database transaction: {}", e);
            CertVerifyError::DbError(e.to_string())
        })?;
        if certs.is_empty() {
            error!("All certificates queried have been revoked or tampered with");
            return Ok(false);
        }
        for model in certs.into_iter() {
            let cert_info = model.cert_info.unwrap();
            match parse_cert_content(&cert_info) {
                Ok(cert) => {
                    info!("Begin verify signature {}", get_cert_serial_number(&cert),);
                    if !CertService::verify_cert_time(&cert) {
                        error!("The parent certificate is expired");
                        continue;
                    }
                    // Obtain certificate public key
                    let pub_key = cert.public_key().unwrap();
                    // Create verifier
                    let mut verifier = match Verifier::new(alg, &pub_key) {
                        Ok(verifier) => verifier,
                        Err(e) => {
                            error!("Failed to get verifier: {}", e);
                            continue;
                        },
                    };
                    // Verify certificate signature
                    if let Err(e) = verifier.update(data) {
                        error!("Failed to update data: {}", e);
                        continue;
                    }
                    match verifier.verify(&signature) {
                        Ok(is_valid) => {
                            if is_valid {
                                info!("Successfully verified certificate signature");
                                return Ok(true);
                            } else {
                                error!("Failed verified certificate signature");
                            }
                        },
                        Err(e) => {
                            error!("Verified certificate signature error: {}", e);
                            continue;
                        },
                    }
                },
                Err(e) => {
                    error!("Parse cert content error: {}", e);
                    continue;
                },
            }
        }
        Ok(false)
    }

    pub async fn verify_cert_chain(cert_type: &str, user_id: &str, cert: &[u8]) -> Result<bool, CertVerifyError> {
        if cert_type.is_empty() && user_id.is_empty() {
            error!("The cert_type or user_id is empty");
            return Ok(false);
        }
        let db = get_connection().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            CertVerifyError::DbError(e.to_string())
        })?;
        let db = db.as_ref();
        let mut service_cert = parse_cert_content(&cert).map_err(|e| {
            error!("Failed to parse cert to X509: {}", e);
            CertVerifyError::VerifyError(e.to_string())
        })?;
        info!("Begin verify certificate chain {:?}", service_cert.subject_name());
        while get_cert_issuer_name(&service_cert) != get_cert_subject_name(&service_cert) {
            let certs: Vec<cert_info::Model> = match CertRepository::find_parent_cert_by_type_and_user(
                db,
                user_id,
                cert_type,
                &get_cert_issuer_name(&service_cert),
            )
            .await
            {
                Ok(certs) => {
                    if certs.is_empty() {
                        error!("The certificate {:?} parent certificates is empty", service_cert.subject_name(),);
                        return Ok(false);
                    }
                    let tx = db.begin().await.map_err(|e| {
                        error!("Failed to get database transaction, {}", e);
                        CertVerifyError::DbError(e.to_string())
                    })?;
                    let certs = Self::filter_is_not_complete_cert(&tx, certs).await;
                    tx.commit().await.map_err(|e| {
                        error!("Failed to commit transaction: {}", e);
                        CertVerifyError::DbError(e.to_string())
                    })?;
                    certs
                },
                Err(e) => {
                    error!("Failed to query certs by type and user: {:?}", e);
                    return Err(CertVerifyError::DbError(e.to_string()));
                },
            };
            if certs.is_empty() {
                error!(
                    "All parent certificates of this certificate {:?} have been revoked or tampered with",
                    service_cert.subject_name(),
                );
                return Ok(false);
            }
            let mut is_success = false;
            for model in certs.into_iter() {
                let cert_info = model.cert_info.unwrap();
                match parse_cert_content(&cert_info) {
                    Ok(parent_cert) => {
                        info!(
                            "Begin verify certificate chain {} {}",
                            get_cert_serial_number(&service_cert),
                            get_cert_serial_number(&parent_cert)
                        );
                        if !CertService::verify_cert_time(&parent_cert) {
                            error!("The parent certificate is expired");
                            continue;
                        }
                        let parent_pub_key = parent_cert.public_key().unwrap();
                        is_success = match service_cert.verify(&parent_pub_key) {
                            Ok(is_success) => {
                                if !is_success {
                                    error!("Verify chain failed");
                                } else {
                                    info!("Verify chain success");
                                    service_cert = parent_cert;
                                }
                                is_success
                            },
                            Err(e) => {
                                error!("Verify chain occur error: {}", e);
                                false
                            },
                        };
                    },
                    Err(e) => {
                        error!("Parse parent certificate occur error: {}", e);
                        continue;
                    },
                }
            }
            if !is_success {
                error!("Not find the certificate {} parent certificate", get_cert_serial_number(&service_cert));
                return Ok(false);
            }
        }
        info!("Certificate chain verification successful");
        Ok(true)
    }
}

// test begin
use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1String;
use openssl::bn::BigNum;
use openssl::x509::X509Builder;
use openssl::x509::{X509Name, X509NameBuilder};

#[test]
fn test_get_cert_subject_name_when_result_not_empty_then_success() {
    // Create a certificate subject with common fields
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_nid(Nid::COMMONNAME, "example.com").unwrap();
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Example Org").unwrap();
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "CN").unwrap();
    let subject_name = name_builder.build();

    let mut cert = X509::builder().unwrap();
    cert.set_subject_name(&subject_name).unwrap();
    let cert = cert.build();

    let result = get_cert_subject_name(&cert);

    // Parse the returned JSON string
    let parsed: BTreeMap<String, String> = serde_json::from_str(&result).unwrap();

    assert_eq!(parsed.get("commonName").unwrap(), "example.com");
    assert_eq!(parsed.get("organizationName").unwrap(), "Example Org");
    assert_eq!(parsed.get("countryName").unwrap(), "CN");
}

#[test]
fn test_get_cert_subject_name_when_result_empty_then_success() {
    // Create an empty certificate subject
    let name_builder = X509NameBuilder::new().unwrap();
    let subject_name = name_builder.build();

    let mut cert = X509::builder().unwrap();
    cert.set_subject_name(&subject_name).unwrap();
    let cert = cert.build();

    let result = get_cert_subject_name(&cert);

    // Empty subject should return an empty JSON object
    assert_eq!(result, "{}");
}

#[test]
fn test_get_cert_subject_name_when_special_chars_then_success() {
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_nid(Nid::COMMONNAME, "321@example.com").unwrap();
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Test & Demo, Inc.").unwrap();
    let subject_name = name_builder.build();

    let mut cert = X509::builder().unwrap();
    cert.set_subject_name(&subject_name).unwrap();
    let cert = cert.build();

    let result = get_cert_subject_name(&cert);

    let parsed: BTreeMap<String, String> = serde_json::from_str(&result).unwrap();

    assert_eq!(parsed.get("commonName").unwrap(), "321@example.com");
    assert_eq!(parsed.get("organizationName").unwrap(), "Test & Demo, Inc.");
}

#[test]
fn test_generate_cert_id_success() {
    // Test basic functionality
    let id1 = generate_cert_id("123", "test-issuer", "user1");
    assert!(!id1.is_empty());
    assert!(!id1.contains("-"));
    assert_eq!(id1.len(), 32);

    // Test that the same input produces the same output
    let id2 = generate_cert_id("123", "test-issuer", "user1");
    assert_eq!(id1, id2);

    // Test that different inputs produce different outputs
    let id3 = generate_cert_id("456", "test-issuer", "user1");
    assert_ne!(id1, id3);

    // Test empty string input
    let id4 = generate_cert_id("", "", "");
    assert!(!id4.is_empty());
    assert_eq!(id4.len(), 32);

    // Test special characters
    let id5 = generate_cert_id("123!@#", "test-issuer$%^", "user1&*()");
    assert!(!id5.is_empty());
    assert_eq!(id5.len(), 32);

    // Test long string
    let long_str = "a".repeat(1000);
    let id6 = generate_cert_id(&long_str, "test-issuer", "user1");
    assert!(!id6.is_empty());
    assert_eq!(id6.len(), 32);
}

#[test]
fn test_generate_cert_id_deterministic_success() {
     // Test determinism: multiple calls should produce the same result
    let inputs = vec![("123", "issuer1", "user1"), ("456", "issuer2", "user2"), ("789", "issuer3", "user3")];

    for (serial, issuer, user) in inputs {
        let id1 = generate_cert_id(serial, issuer, user);
        let id2 = generate_cert_id(serial, issuer, user);
        assert_eq!(id1, id2, "Generated IDs should be deterministic");
    }
}

#[test]
fn test_generate_cert_id_uniqueness_success() {
    // Test uniqueness: different inputs should produce different outputs
    let id1 = generate_cert_id("123", "issuer1", "user1");
    let id2 = generate_cert_id("123", "issuer1", "user2");
    let id3 = generate_cert_id("123", "issuer2", "user1");
    let id4 = generate_cert_id("456", "issuer1", "user1");

    let ids = vec![id1, id2, id3, id4];
    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique_ids.len(), "All generated IDs should be unique");
}


#[test]
fn test_get_cert_serial_number_success() {
    // Create a test certificate
    let mut builder = X509Builder::new().unwrap();

    // Set a known serial number
    let serial = BigNum::from_dec_str("123456789").unwrap();
    let serial_asn1 = Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();

    let cert = builder.build();

    // Test getting the serial number
    let result = get_cert_serial_number(&cert);
    assert_eq!(result, "075bcd15");  // Hexadecimal representation of 123456789
}

#[test]
fn test_get_cert_serial_number_when_serial_large_then_success() {
    // Create a test certificate
    let mut builder = X509Builder::new().unwrap();

    // Set a large serial number
    let serial = BigNum::from_dec_str("340282366920938463463374607431768211456").unwrap();  // 2^128
    let serial_asn1 = Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();

    let cert = builder.build();

    // Test getting the serial number
    let result = get_cert_serial_number(&cert);
    assert_eq!(result, "0100000000000000000000000000000000");
}

#[test]
fn test_get_cert_serial_when_number_zero_then_success() {
    // Create a test certificate
    let mut builder = X509Builder::new().unwrap();

    // Set serial number to 0
    let serial = BigNum::from_dec_str("0").unwrap();
    let serial_asn1 = Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();

    let cert = builder.build();

    // Test getting the serial number
    let result = get_cert_serial_number(&cert);
    assert_eq!(result, "");
}

#[test]
fn test_get_cert_issuer_name_when_result_not_empty_then_success() {
    // Create a certificate issuer with standard fields
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_nid(Nid::COMMONNAME, "Test CA").unwrap();
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Test Org").unwrap();
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "CN").unwrap();
    let name = name_builder.build();

    let mut cert = X509::builder().unwrap();
    cert.set_issuer_name(&name).unwrap();
    let cert = cert.build();

    let result = get_cert_issuer_name(&cert);

    // Verify the result is a valid JSON string
    let parsed: BTreeMap<String, String> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.get("commonName").unwrap(), "Test CA");
    assert_eq!(parsed.get("organizationName").unwrap(), "Test Org");
    assert_eq!(parsed.get("countryName").unwrap(), "CN");
}

#[test]
fn test_get_cert_issuer_name_when_result_empty_then_success() {
    // Create an empty certificate issuer
    let name = X509NameBuilder::new().unwrap().build();

    let mut cert = X509::builder().unwrap();
    cert.set_issuer_name(&name).unwrap();
    let cert = cert.build();

    let result = get_cert_issuer_name(&cert);

    // Verify the result is an empty JSON object string
    assert_eq!(result, "{}");
}

#[test]
fn test_get_cert_issuer_name_when_special_chars_then_success() {
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_nid(Nid::COMMONNAME, "Test CA Special Characters !@#$%^").unwrap();
    let name = name_builder.build();

    let mut cert = X509::builder().unwrap();
    cert.set_issuer_name(&name).unwrap();
    let cert = cert.build();

    let result = get_cert_issuer_name(&cert);

    // Verify that the result handles special characters correctly
    let parsed: BTreeMap<String, String> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.get("commonName").unwrap(), "Test CA Special Characters !@#$%^");
}

#[test]
fn test_get_cert_issuer_name_when_multiple_values_then_success() {
    // Create a certificate issuer with multiple fields of the same type
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Unit1").unwrap();
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Unit2").unwrap();
    let name = name_builder.build();

    let mut cert = X509::builder().unwrap();
    cert.set_issuer_name(&name).unwrap();
    let cert = cert.build();

    let result = get_cert_issuer_name(&cert);

    // Verify the result correctly handles multiple values
    let parsed: BTreeMap<String, String> = serde_json::from_str(&result).unwrap();
    assert!(parsed.get("organizationalUnitName").unwrap().contains("Unit2"));
}

#[test]
fn test_convert_to_query_response_when_certs_empty_then_success() {
    let certs = Vec::new();
    let response = CertService::convert_to_query_response(certs);
    assert!(response.message.is_none());
    assert!(response.certs.is_empty());
}

#[test]
fn test_convert_to_query_response_when_without_revoked_then_success() {
    let cert = cert_info::Model {
        id: "test_id".to_string(),
        name: Some("test_name".to_string()),
        description: Some("test_description".to_string()),
        cert_info: Some(Vec::from("test_content")),
        cert_type: Some(json!(["test_type"])),
        is_default: Some(true),
        version: Some(1),
        create_time: Some(1234567890),
        update_time: Some(1234567890),
        valid_code: Some(1),
        ..Default::default()
    };

    let certs = vec![(cert, None)];
    let response = CertService::convert_to_query_response(certs);

    assert!(response.message.is_none());
    assert_eq!(response.certs.len(), 1);
    let cert_resp = &response.certs[0];
    assert_eq!(cert_resp.cert_id, Some("test_id".to_string()));
    assert_eq!(cert_resp.cert_name, Some("test_name".to_string()));
    assert_eq!(cert_resp.description, Some("test_description".to_string()));
    assert_eq!(cert_resp.content, Some("test_content".to_string()));
    assert_eq!(cert_resp.cert_type, Some(vec!["test_type".to_string()]));
    assert_eq!(cert_resp.is_default, Some(true));
    assert_eq!(cert_resp.version, Some(1));
    assert_eq!(cert_resp.create_time, Some(1234567890));
    assert_eq!(cert_resp.update_time, Some(1234567890));
    assert_eq!(cert_resp.valid_code, Some(1));
    assert!(cert_resp.cert_revoked_date.is_none());
    assert!(cert_resp.cert_revoked_reason.is_none());
}

#[test]
fn test_convert_to_query_response_when_with_revoked_then_success() {
    let cert = cert_info::Model {
        id: "test_id".to_string(),
        name: Some("test_name".to_string()),
        cert_type: Some(json!(["test_type"])),
        valid_code: Some(2), // revoked
        ..Default::default()
    };
    let revoked = cert_revoked_list::Model {
        id: "test_id".to_string(),
        cert_revoked_date: Some(1234567890),
        cert_revoked_reason: Some("test_reason".to_string()),
        ..Default::default()
    };

    let certs = vec![(cert, Some(revoked))];
    let response = CertService::convert_to_query_response(certs);

    assert!(response.message.is_none());
    assert_eq!(response.certs.len(), 1);
    let cert_resp = &response.certs[0];
    assert_eq!(cert_resp.cert_id, Some("test_id".to_string()));
    assert_eq!(cert_resp.cert_name, Some("test_name".to_string()));
    assert_eq!(cert_resp.cert_type, Some(vec!("test_type".to_string())));
    assert_eq!(cert_resp.valid_code, Some(2));
    assert_eq!(cert_resp.cert_revoked_date, Some(1234567890));
    assert_eq!(cert_resp.cert_revoked_reason, Some("test_reason".to_string()));
}

#[test]
fn test_convert_to_query_response_when_multiple_certs_then_success() {
    let cert1 =
        cert_info::Model { id: "test_id_1".to_string(), name: Some("test_name_1".to_string()), ..Default::default() };

    let cert2 =
        cert_info::Model { id: "test_id_2".to_string(), name: Some("test_name_2".to_string()), ..Default::default() };

    let revoked = cert_revoked_list::Model {
        id: "test_id_2".to_string(),
        cert_revoked_date: Some(1234567890),
        cert_revoked_reason: Some("test_reason".to_string()),
        ..Default::default()
    };

    let certs = vec![(cert1, None), (cert2, Some(revoked))];
    let response = CertService::convert_to_query_response(certs);

    assert!(response.message.is_none());
    assert_eq!(response.certs.len(), 2);

    // Verify the first certificate (not revoked)
    let cert_resp1 = &response.certs[0];
    assert_eq!(cert_resp1.cert_id, Some("test_id_1".to_string()));
    assert_eq!(cert_resp1.cert_name, Some("test_name_1".to_string()));
    assert!(cert_resp1.cert_revoked_date.is_none());
    assert!(cert_resp1.cert_revoked_reason.is_none());

    // Verify the second certificate (revoked)
    let cert_resp2 = &response.certs[1];
    assert_eq!(cert_resp2.cert_id, Some("test_id_2".to_string()));
    assert_eq!(cert_resp2.cert_name, Some("test_name_2".to_string()));
    assert_eq!(cert_resp2.cert_revoked_date, Some(1234567890));
    assert_eq!(cert_resp2.cert_revoked_reason, Some("test_reason".to_string()));
}