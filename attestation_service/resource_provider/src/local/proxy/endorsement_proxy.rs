use crate::resource_facade::endorsement::Endorsement;
use actix_web::{web, HttpRequest, HttpResponse};
use endorserment::services::cert_service::{AddCertRequest, CertService, DeleteRequest, QueryInfo, UpdateCertRequest};
use sea_orm::DatabaseConnection;
use serde_json::Value;
use std::sync::{Arc, OnceLock};
use common_log::error;

pub struct EndorsementProxy;

static ENDORSEMENT_PROXY_INSTANCE: OnceLock<Arc<EndorsementProxy>> = OnceLock::new();

impl EndorsementProxy {
    pub(crate) fn new() -> Self {
        Self
    }

    pub fn instance() -> &'static Arc<EndorsementProxy> {
        ENDORSEMENT_PROXY_INSTANCE.get_or_init(|| Arc::new(EndorsementProxy::new()))
    }
}

impl Endorsement for EndorsementProxy {
    async fn get_certs(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        query: web::Query<Value>,
        req: HttpRequest,
    ) -> HttpResponse {
        let json_string = query.to_string();
        let query: QueryInfo = match serde_json::from_str(&json_string) {
            Ok(query) => query,
            Err(err) => return HttpResponse::BadRequest().body(format!("{}", err)),
        };
        let ids: Option<Vec<String>> =
            if let Some(ids) = query.ids { Some(ids.split(',').map(String::from).collect()) } else { None };
        if let Some(user_id) = req.headers().get("User-Id") {
            if let Ok(user_id) = user_id.to_str() {
                return CertService::get_all_certs(db, &ids, &query.cert_type, user_id).await.unwrap_or_else(|e| {
                    error!("Failed to fetch certs: {:?}", e);
                    HttpResponse::InternalServerError().body("Failed to query certs")
                });
            }
        }
        HttpResponse::BadRequest().body("Failed to query cert")
    }

    async fn add_cert(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        add_cert: web::Json<Value>,
        req: HttpRequest,
    ) -> HttpResponse {
        let json_string = add_cert.to_string();
        let add_cert: AddCertRequest = match serde_json::from_str(&json_string) {
            Ok(add_cert) => add_cert,
            Err(err) => return HttpResponse::BadRequest().body(format!("{}", err)),
        };
        if let Some(user_id) = req.headers().get("User-Id") {
            if let Ok(user_id) = user_id.to_str() {
                return CertService::add_cert(db, add_cert, user_id).await.unwrap_or_else(|e| {
                    error!("Failed to add cert: {:?}", e);
                    HttpResponse::InternalServerError().body("Failed to add cert")
                });
            }
        }
        HttpResponse::BadRequest().body("Failed to add cert")
    }

    async fn delete_cert(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        delete_request: web::Json<Value>,
        req: HttpRequest,
    ) -> HttpResponse {
        let json_string = delete_request.to_string();
        let delete_request: DeleteRequest = match serde_json::from_str(&json_string) {
            Ok(delete_request) => delete_request,
            Err(err) => return HttpResponse::BadRequest().body(format!("{}", err)),
        };
        if let Some(user_id) = req.headers().get("User-Id") {
            if let Ok(user_id) = user_id.to_str() {
                return CertService::delete_certs(db, delete_request, user_id).await.unwrap_or_else(|e| {
                    error!("Failed to delete certs: {:?}", e);
                    HttpResponse::InternalServerError().body("Failed to delete certs")
                });
            }
        }
        HttpResponse::BadRequest().body("Failed to delete certs")
    }

    async fn update_cert(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        update_cert: web::Json<Value>,
        req: HttpRequest,
    ) -> HttpResponse {
        let json_string = update_cert.to_string();
        let update_cert: UpdateCertRequest = match serde_json::from_str(&json_string) {
            Ok(update_cert) => update_cert,
            Err(err) => return HttpResponse::BadRequest().body(format!("{}", err)),
        };
        if let Some(user_id) = req.headers().get("User-Id") {
            if let Ok(user_id) = user_id.to_str() {
                return CertService::update_cert(db, update_cert, user_id.to_string()).await.unwrap_or_else(|e| {
                    error!("Failed to add cert: {:?}", e);
                    HttpResponse::InternalServerError().body("Failed to add cert")
                });
            }
        }
        HttpResponse::BadRequest().body("Failed to add cert")
    }
}
