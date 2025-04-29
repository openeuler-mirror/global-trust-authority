use std::sync::{Arc, OnceLock};
use actix_web::{web, HttpRequest, HttpResponse};
use sea_orm::DatabaseConnection;
use policy::services::policy_service::PolicyService;
use serde_json::json;
use common_log::info;
use crate::resource_facade::Policy;

pub struct PolicyProxy;

static POLICY_PROXY_INSTANCE: OnceLock<Arc<PolicyProxy>> = OnceLock::new();

impl PolicyProxy {
    pub(crate) fn new() -> Self {
        Self
    }

    pub fn instance() -> &'static Arc<PolicyProxy> {
        POLICY_PROXY_INSTANCE.get_or_init(|| Arc::new(PolicyProxy::new()))
    }

    fn validate_user_id(&self, req: &HttpRequest) -> Option<HttpResponse> {
        if req.headers().get("User-Id").is_none() {
            return Some(HttpResponse::BadRequest().json(json!({
                "message": "Missing or Invalid User-Id header",
            })));
        }
        None
    }
}

impl Policy for PolicyProxy {
    async fn add_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse {
        info!("Received request to add policy");
        if let Some(err) = self.validate_user_id(&req) {
            return err;
        }
        match PolicyService::add_policy(req, db, req_body).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }

    async fn update_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse {
        info!("Received request to update policy");
        if let Some(err) = self.validate_user_id(&req) {
            return err;
        }
        match PolicyService::update_policy(req, db, req_body).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }

    async fn delete_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse {
        info!("Received request to delete policy");
        if let Some(err) = self.validate_user_id(&req) {
            return err;
        }
        match PolicyService::delete_policy(req, db, req_body).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }

    async fn query_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>) -> HttpResponse {
        info!("Received request to query policy");
        let query_params = web::Query::<serde_json::Value>::from_query(req.query_string()).unwrap_or_else(|_| web::Query(serde_json::json!({})));
        match PolicyService::query_policy(req, db, query_params).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }

    fn test(&self) {
        println!("hello world");
    }
}