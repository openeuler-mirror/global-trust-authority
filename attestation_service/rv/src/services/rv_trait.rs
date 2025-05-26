use std::future::Future;
use crate::entities::inner_model::rv_model::{RefValueModel, RefValueModelBuilder};
use crate::entities::request_body::rv_add_req_body::RvAddReqBody;
use crate::entities::request_body::rv_del_req_body::RvDelReqBody;
use crate::entities::request_body::rv_update_req_body::RvUpdateReqBody;
use crate::error::ref_value_error::RefValueError;
use crate::error::ref_value_error::RefValueError::{InvalidParameter, JsonParseError, VerifyError};
use crate::utils::utils::Utils;
use actix_web::web::{Json, Query};
use actix_web::{web, HttpRequest, HttpResponse};
use endorserment::services::cert_service::CertService;
use jwt::jwt_parser::JwtParser;
use log::{error, info};
use sea_orm::DatabaseConnection;
use serde_json::{from_value, Map, Value};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::pin::Pin;
use std::sync::Arc;
use serde::Serialize;
use validator::Validate;
use crate::entities::request_body::validator::Validator;
use crate::repositories::rv_db_repo::RvDbRepo;
use config_manager::types::CONFIG;

#[allow(async_fn_in_trait)]
pub trait RefValueTrait {
    async fn add(
        &self,
        conn: web::Data<Arc<DatabaseConnection>>,
        rv_model: &RefValueModel,
    ) -> Result<(), RefValueError>;

    async fn update(
        &self,
        conn: web::Data<Arc<DatabaseConnection>>,
        user_id: &str,
        update_req_body: &RvUpdateReqBody,
    ) -> Result<(i32, String), RefValueError>;

    async fn delete(
        &self,
        conn: web::Data<Arc<DatabaseConnection>>,
        user_id: &str,
        del_type: &str,
        del_req_body: &RvDelReqBody,
    ) -> Result<(), RefValueError>;
    
    /// Adds a new reference value to the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the reference value data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn add_ref_value(
        &self,
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        req_body: Json<Value>,
    ) -> Result<HttpResponse, RefValueError> {
        let user_id = extract_user_id(&req)?;
        let add_rv_body = parse_and_validate::<RvAddReqBody>(req_body)?;
        verify_by_cert(&user_id, &add_rv_body.content).await?;
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
            .is_default(add_rv_body.is_default.unwrap_or(false))
            .build();
        let is_require_sign = CONFIG.get_instance().unwrap().attestation_service.key_management.is_require_sign;
        if is_require_sign {
            let (signature, key_version) = Utils::sign_by_ref_value_model(&rv_model).await?;
            rv_model.set_signature(&signature);
            rv_model.set_key_version(&key_version);
        }

        self.add(db, &rv_model).await?;

        info!("Ref value added successfully");
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "refvalue": {
                "id": rv_model.id,
                "version": "1",
                "name": add_rv_body.name
            }
        })))
    }

    /// Updates an existing reference value in the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the updated reference value data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn update_ref_value(
        &self,
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        req_body: Json<Value>,
    ) -> Result<HttpResponse, RefValueError> {
        let user_id = extract_user_id(&req)?;
        // 1、参数校验
        let update_rv_body = parse_and_validate::<RvUpdateReqBody>(req_body)?;

        if update_rv_body.content.is_some() {
            verify_by_cert(&user_id, &update_rv_body.content.clone().unwrap()).await?;
        }

        let (version, name) = self.update(db, &user_id, &update_rv_body).await?;

        info!("Reference Value updated successfully");
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "refvalue": {
                "id": update_rv_body.id,
                "version": version,
                "name": name
            }
        })))
    }

    /// Deletes an existing reference value from the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the reference value identifier
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn delete_ref_value(
        &self,
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        req_body: web::Json<serde_json::Value>,
    ) -> Result<HttpResponse, RefValueError> {
        let user_id = extract_user_id(&req)?;
        let rv_del_req_body = parse_and_validate::<RvDelReqBody>(req_body)?;
        let delete_type = rv_del_req_body.delete_type.as_str();

        self.delete(db, &user_id, &delete_type, &rv_del_req_body)
            .await
            .map(|_| {
                info!("Reference Value deleted successfully");
                HttpResponse::Ok().finish()
            })
            .map_err(|e| {
                error!("Failed to delete Reference Value: {:?}", e.to_string());
                e
            })
    }

    /// Queries reference value based on provided parameters.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and query parameters
    /// * `db` - Database connection wrapped in web::Data
    ///
    /// # Returns
    /// * `HttpResponse` - Response containing the query results or error message
    async fn query_ref_value(
        &self,
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
    ) -> Result<HttpResponse, RefValueError> {
        let user_id = extract_user_id(&req)?;
        let query_params = Query::<Value>::from_query(req.query_string())
            .map_err(|e| InvalidParameter(format!("Invalid query parameters: {}", e)))?;
        if let Some(ids) = extract_ids_param(&query_params)? {
            return handle_response(RvDbRepo::query_by_ids(&db, &user_id, &ids).await);
        }
        let res: Result<Vec<_>, RefValueError>;
        if let Some(attester_type) = extract_attester_type(&query_params)? {
            res = RvDbRepo::query_all_by_attester_type(&db, &user_id, attester_type).await
        } else {
            res = RvDbRepo::query_all(&db, &user_id).await
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
        handle_response(standard_res)
    }

    fn verify<'a>(&'a self, measurements: &'a Vec<String>, user_id: &'a str, attester_type: &'a str) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;
}

fn extract_user_id(req: &HttpRequest) -> Result<String, RefValueError> {
    req.headers()
        .get("User-Id")
        .and_then(|id| id.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(InvalidParameter("Missing User-Id header".to_string()))
}

fn parse_and_validate<T: Validate + for<'de> serde::Deserialize<'de>>(
    req_body: Json<Value>,
) -> Result<T, RefValueError> {
    let body: T = from_value(req_body.into_inner()).map_err(|e| JsonParseError(e.to_string()))?;
    body.validate().map_err(|e| InvalidParameter(e.to_string()))?;
    Ok(body)
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
