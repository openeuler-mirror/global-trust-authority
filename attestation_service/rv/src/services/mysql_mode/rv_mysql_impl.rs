use crate::entities::db_model::rv_db_model::{ActiveModel, ActiveModelBuilder, Model as RvDbModel};
use crate::entities::db_model::rv_detail_db_model::Model as RvDtlDbModel;
use crate::entities::inner_model::rv_content::{RefValueDetail, RefValueDetails};
use crate::entities::inner_model::rv_model::RefValueModelBuilder;
use crate::entities::request_body::rv_add_req_body::RvAddReqBody;
use crate::entities::request_body::rv_del_req_body::RvDelReqBody;
use crate::entities::request_body::rv_update_req_body::RvUpdateReqBody;
use crate::entities::request_body::validator::Validator;
use crate::error::ref_value_error::RefValueError;
use crate::error::ref_value_error::RefValueError::{DbError, InvalidParameter, JsonParseError, VerifyError};
use crate::repositories::rv_db_repo::RvDbRepo;
use crate::repositories::rv_dtl_db_repo::RvDtlDbRepo;
use crate::services::ref_value::RefValue;
use crate::utils::utils::Utils;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use endorserment::services::cert_service::CertService;
use jwt::jwt_parser::JwtParser;
use key_management::api::{CryptoOperations, DefaultCryptoImpl};
use log::{error, info};
use config_manager::types::CONFIG;
use rdb::get_connection;
use sea_orm::ActiveValue::Set;
use sea_orm::DatabaseConnection;
use serde::Serialize;
use serde_json::{from_str, from_value, Map, Value};
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use futures::{stream, StreamExt};
use validator::Validate;

pub struct RvMysqlImpl;

impl RvMysqlImpl {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl RefValue for RvMysqlImpl {
    async fn add_ref_value(
        &self,
        req: HttpRequest,
        db: Data<Arc<DatabaseConnection>>,
        req_body: Json<Value>,
    ) -> Result<HttpResponse, RefValueError> {
        // Parse userId
        let user_id = Self::extract_user_id(&req)?;
        // 1. Parameter validation
        let add_rv_body = Self::parse_and_validate::<RvAddReqBody>(req_body)?;

        // Parse and verify JWT
        Self::verify_by_cert(&user_id, &add_rv_body.content).await?;

        let id = {
            let mut hasher = DefaultHasher::new();
            let _ = &user_id.hash(&mut hasher);
            let _ = &add_rv_body.name.hash(&mut hasher);
            let _ = &add_rv_body.attester_type.hash(&mut hasher);
            hasher.finish().to_string()
        };

        let mut rv_model = RefValueModelBuilder::new()
            .id(&id)
            .uid(&user_id)
            .name(&add_rv_body.name)
            .op_description(&add_rv_body.description)
            .attester_type(&add_rv_body.attester_type)
            .content(&add_rv_body.content)
            .build();
        let is_require_sign = CONFIG.get_instance().unwrap().attestation_service.key_management.is_require_sign;
        if is_require_sign {
            let (signature, key_version) = Utils::sign_by_ref_value_model(&rv_model).await?;
            rv_model.set_signature(&signature);
            rv_model.set_key_version(&key_version);
        }
        RvDbRepo::add_ref_value(&db, &rv_model, 100).await.map_err(|e| {
            error!("Ref value added failed: {}", e);
            DbError(e.to_string())
        })?;

        info!("Ref value added successfully");
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "id": rv_model.id,
            "version": "0",
            "name": add_rv_body.name
        })))
    }

    async fn update_ref_value(
        &self,
        req: HttpRequest,
        db: Data<Arc<DatabaseConnection>>,
        req_body: Json<Value>,
    ) -> Result<HttpResponse, RefValueError> {
        // Parse userId
        let user_id = Self::extract_user_id(&req)?;
        // 1. Parameter validation
        let update_rv_body = Self::parse_and_validate::<RvUpdateReqBody>(req_body)?;

        if update_rv_body.content.is_some() {
            Self::verify_by_cert(&user_id, &update_rv_body.content.clone().unwrap()).await?;
        }

        let (version, name) =
            RvDbRepo::update_ref_value(&db, &user_id, &update_rv_body.id, &update_rv_body).await.map_err(|e| {
                error!("Reference value update failed: {}", e);
                e
            })?;

        info!("Reference Value updated successfully");
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "id": update_rv_body.id,
            "version": version,
            "name": name
        })))
    }

    async fn delete_ref_value(
        &self,
        req: HttpRequest,
        db: Data<Arc<DatabaseConnection>>,
        req_body: Json<Value>,
    ) -> Result<HttpResponse, RefValueError> {
        let user_id = Self::extract_user_id(&req)?;
        let rv_del_req_body = Self::parse_and_validate::<RvDelReqBody>(req_body)?;
        let delete_type = rv_del_req_body.delete_type.as_str();

        let result = match delete_type {
            "all" => RvDbRepo::del_all_ref_value(&db, &user_id).await,
            "id" => RvDbRepo::del_ref_value_by_id(&db, &user_id, &rv_del_req_body.ids.unwrap()).await,
            "type" => RvDbRepo::del_ref_value_by_type(&db, &user_id, &rv_del_req_body.attester_type.unwrap()).await,
            _ => Err(InvalidParameter(format!("Invalid delete_type: {}", rv_del_req_body.delete_type))),
        };
        result
            .map(|_| {
                info!("Reference Value deleted successfully");
                HttpResponse::Ok().finish()
            })
            .map_err(|e| {
                error!("Failed to delete Reference Value: {:?}", e.to_string());
                e
            })
    }

    async fn query_ref_value(
        &self,
        req: HttpRequest,
        db: Data<Arc<DatabaseConnection>>,
    ) -> Result<HttpResponse, RefValueError> {
        let user_id = Self::extract_user_id(&req)?;
        let query_params = Query::<Value>::from_query(req.query_string())
            .map_err(|e| InvalidParameter(format!("Invalid query parameters: {}", e)))?;
        if let Some(ids) = Self::extract_ids_param(&query_params)? {
            return Self::handle_response(RvDbRepo::query_ref_value_by_ids(&db, &user_id, &ids).await);
        }
        let res: Result<Vec<_>, RefValueError>;
        if let Some(attester_type) = Self::extract_attester_type(&query_params)? {
            res = RvDbRepo::query_ref_value_ids_by_attester_type(&db, &user_id, attester_type).await
        } else {
            res = RvDbRepo::query_all_ref_value_ids(&db, &user_id).await
        }
        let standard_res = res.map(|vec_model| {
            let response_list: Vec<Map<String, Value>> = vec_model
                .iter()
                .map(|m| {
                    let mut response = serde_json::Map::new();
                    response.insert("id".to_string(), Value::String(m.id.to_string()));
                    response.insert("name".to_string(), Value::String(m.name.to_string()));
                    response.insert("attester_type".to_string(), Value::String(m.attester_type.to_string()));
                    response
                })
                .collect();
            response_list
        });
        Self::handle_response(standard_res)
    }

    async fn verify(measurements: Vec<&str>, user_id: &str, attester_type: &str) -> (bool, Vec<String>) {
        let conn = match get_connection().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Database connection failed: {}", e);
                return (false, measurements.into_iter().map(String::from).collect());
            }
        };
        let is_require_sign = CONFIG.get_instance().unwrap().attestation_service.key_management.is_require_sign;
        if is_require_sign {
            // Query baseline main table id, content and other fields by user_id and attester_type, verify signature, only use successfully verified parts, asynchronously update valid_code for failed verifications, need pagination, query 10 records at a time
            // Query detail table by main table id, compare hashCode with content in detail table, check if measurements are included after matching
            Self::verify_with_sign(&conn, measurements, user_id, attester_type).await
        } else {
            Self::verify_without_sign(&conn, measurements, user_id, attester_type).await
        }
    }
}

impl RvMysqlImpl {
    async fn verify_without_sign(conn: &DatabaseConnection,
                                 measurements: Vec<&str>,
                                 user_id: &str,
                                 attester_type: &str,) -> (bool, Vec<String>) {
        let measurements_set: HashSet<&str> = measurements.iter().copied().collect();
        let mut matched: HashSet<String> = HashSet::new();
        let mut all_success = true;
        
        let mut page = 0;
        loop {
            let dtl_page = match RvDtlDbRepo::query_page_rv_dtl_by_attester_type_and_uid(
                conn, attester_type, user_id, page, 1000
            ).await {
                Ok(page) => page,
                Err(e) => {
                    error!("Query failed on page {}: {}", page, e);
                    all_success = false;
                    break;
                }
            };

            // 3. Handle empty page case
            if dtl_page.is_empty() {
                break;
            }

            // 4. Batch match measurements
            for dtl in dtl_page {
                if measurements_set.contains(dtl.sha256.as_str()) {
                    matched.insert(dtl.sha256);
                }
            }

            page += 1;
        }

        // 5. Calculate unmatched measurements
        let unmatched: Vec<String> = measurements
            .into_iter()
            .filter(|m| !matched.contains(*m))
            .map(String::from)
            .collect();

        (all_success, unmatched)
    }

    async fn verify_with_sign(
        conn: &DatabaseConnection,
        measurements: Vec<&str>,
        user_id: &str,
        attester_type: &str,
    ) -> (bool, Vec<String>) {
        // 1. Pre-calculate measurement set
        let measurements_set: HashSet<&str> = measurements.iter().copied().collect();
        let mut matched = HashSet::new();
        let mut all_success = true;

        // 2. Stream process paginated data
        let mut page = 0;
        loop {
            // 2.1 Get main table data page
            let rv_models = match RvDbRepo::query_page_ref_value_by_attester_type_and_uid(
                conn, attester_type, user_id, page, 10
            ).await {
                Ok(models) => models,
                Err(e) => {
                    error!("Query main table failed: {}", e);
                    all_success = false;
                    break;
                }
            };

            if rv_models.is_empty() {
                break;
            }

            // 2.2 Parallel verify signatures and filter invalid items
            let verified_models: Vec<_> = stream::iter(rv_models)
                .filter_map(|model| async move {
                    Self::verify_sig(conn, model.clone()).await.then_some(model)
                })
                .collect()
                .await;

            // 2.3 Get valid ID set
            let valid_ids: Vec<_> = verified_models.iter()
                .map(|m| m.id.as_str())
                .collect();

            // 2.4 Query details and calculate hash
            if let Ok(details) = RvDtlDbRepo::query_rv_details_by_ids(conn, valid_ids).await {
                // Create fast lookup table
                let sha256_map: HashMap<String, String> = details.iter()
                    .map(|dtl| (dtl.id.clone(), dtl.sha256.clone()))
                    .collect();

                let rv_hashes = Self::convert_rv_models_to_map(verified_models);
                let dtl_hashes = Self::convert_rv_dtls_to_map(details);

                for (id, rv_hash) in rv_hashes {
                    if dtl_hashes.get(&id) == Some(&rv_hash) {
                        if let Some(sha256) = sha256_map.get(&id) {
                            if measurements_set.contains(sha256.as_str()) {
                                matched.insert(sha256.clone());
                            }
                        }
                    }
                }
            }

            page += 1;
        }

        // 3. Calculate unmatched items
        let unmatched = measurements
            .into_iter()
            .filter(|m| !matched.contains(*m))
            .map(String::from)
            .collect();

        (all_success, unmatched)
    }
    fn convert_rv_dtls_to_map(rv_dtls: Vec<RvDtlDbModel>) -> HashMap<String, u64> {
        let mut ori_map: HashMap<String, Vec<RefValueDetail>> = HashMap::new();
        for db_dtl in rv_dtls {
            let value = serde_json::json!({
                "file_name": db_dtl.file_name,
                "sha256": db_dtl.sha256,
            });
            let dtl: RefValueDetail = from_value(value).unwrap();
            let id = db_dtl.id;
            if ori_map.contains_key(&id) {
                ori_map.get_mut(&id).unwrap().push(dtl);
            } else {
                ori_map.insert(id, vec![dtl]);
            }
        }
        ori_map
            .into_iter()
            .map(|(id, vec)| {
                let details = RefValueDetails { reference_values: vec };
                let mut hasher = DefaultHasher::new();
                details.hash(&mut hasher);
                (id, hasher.finish())
            })
            .collect()
    }

    fn convert_rv_models_to_map(rv_models: Vec<RvDbModel>) -> HashMap<String, u64> {
        rv_models
            .into_iter()
            .filter_map(|model| {
                let rv_content_str = match JwtParser::get_payload(&model.content) {
                    Ok(content) => content,
                    Err(e) => {
                        error!("Failed to parse RV content to JWT payload: {}", e);
                        return None;
                    },
                };

                let rv_content: RefValueDetails = match from_str(&rv_content_str) {
                    Ok(content) => content,
                    Err(e) => {
                        error!("Failed to parse RV content JSON: {}", e);
                        return None;
                    },
                };

                let mut hasher = DefaultHasher::new();
                rv_content.hash(&mut hasher);
                Some((model.id, hasher.finish()))
            })
            .collect()
    }

    async fn verify_sig(conn: &DatabaseConnection, model: RvDbModel) -> bool {
        let active_model: ActiveModel = model.into();
        let data = match Utils::encode_rv_db_model_to_bytes(active_model.clone().into()) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to query total page when verify measurements: {}", e);
                return false;
            },
        };
        match DefaultCryptoImpl
            .verify("FSK", Some(&active_model.key_version.unwrap()), data, active_model.signature.unwrap())
            .await
        {
            Ok(true) => true,
            Ok(false) => {
                let id = active_model.id.unwrap();
                let version = active_model.version.unwrap();
                let update_valid_code_model = ActiveModelBuilder::new().valid_code(1).build();
                if let Err(e) =
                    RvDbRepo::update_rv_main_by_id_and_version(conn, update_valid_code_model, &id, version).await
                {
                    error!("Failed to update invalid code by query: {}", e);
                };
                false
            },
            Err(e) => {
                error!("Failed to verify reference value: {}", e);
                false
            },
        }
    }

    fn parse_and_validate<T: Validate + for<'de> serde::Deserialize<'de>>(
        req_body: Json<Value>,
    ) -> Result<T, RefValueError> {
        let body: T = from_value(req_body.into_inner()).map_err(|e| JsonParseError(e.to_string()))?;
        body.validate().map_err(|e| InvalidParameter(e.to_string()))?;
        Ok(body)
    }

    fn extract_user_id(req: &HttpRequest) -> Result<String, RefValueError> {
        req.headers()
            .get("User-Id")
            .and_then(|id| id.to_str().ok())
            .map(|s| s.to_string())
            .ok_or(InvalidParameter("Missing User-Id header".to_string()))
    }

    fn extract_ids_param(query_params: &Query<Value>) -> Result<Option<Vec<String>>, RefValueError> {
        if let Some(ids_value) = query_params.get("ids") {
            let ids_str = ids_value.as_str().ok_or(InvalidParameter("ids parameter must be a string".to_string()))?;

            let ids = ids_str.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>();

            Validator::validate_ids_could_none(&Some(ids.clone())).map_err(|e| InvalidParameter(e.to_string()))?;

            Ok(Some(ids))
        } else {
            Ok(None)
        }
    }

    fn extract_attester_type(query_params: &Query<Value>) -> Result<Option<&str>, RefValueError> {
        if let Some(attester_type_value) = query_params.get("attester_type") {
            let attester_type = attester_type_value
                .as_str()
                .ok_or(InvalidParameter("attester_type parameter must be a string".to_string()))?;

            Validator::validate_attester_type_could_none(&Some(attester_type.to_string()))
                .map_err(|e| InvalidParameter(e.to_string()))?;

            Ok(Some(attester_type))
        } else {
            Ok(None)
        }
    }

    async fn verify_by_cert(user_id: &str, content: &str) -> Result<(), RefValueError> {
        let alg = JwtParser::get_alg(content).map_err(|e| InvalidParameter(e.to_string()))?;
        let signature = JwtParser::get_signature(content).map_err(|e| InvalidParameter(e.to_string()))?;
        let base_data = JwtParser::get_base_data(content);
        let verify_res =
            match CertService::verify_by_cert("refvalue", &user_id, &signature, alg, &base_data.as_bytes()).await {
                Ok(verify_res) => verify_res,
                Err(e) => {
                    error!("reference value verify failed: {:?}", e);
                    return Err(VerifyError(e.to_string()));
                },
            };
        if !verify_res {
            return Err(VerifyError("Failed to verify reference value signature".to_string()));
        }
        Ok(())
    }

    fn handle_response<T: Serialize>(res: Result<Vec<T>, RefValueError>) -> Result<HttpResponse, RefValueError> {
        match res {
            Ok(query_res) => {
                let mut response = serde_json::Map::new();
                response.insert("ref_values".to_string(), serde_json::to_string(&query_res).unwrap().parse()?);
                Ok(HttpResponse::Ok().json(response))
            },
            Err(e) => {
                error!("Failed to query Reference Value: {:?}", e.to_string());
                Err(e)
            },
        }
    }
}
