use std::sync::Arc;
use actix_web::{HttpRequest, HttpResponse};
use actix_web::web::{Data, Json};
use sea_orm::DatabaseConnection;
use serde_json::Value;
use crate::resource_facade::Rv;

pub struct RvImpl;

impl RvImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Rv for RvImpl {
    async fn add_ref_value(&self, req: HttpRequest, db: Data<Arc<DatabaseConnection>>, req_body: Json<Value>) -> HttpResponse {
        HttpResponse::InternalServerError().body("The independent deployment feature is not supported")
    }

    async fn update_ref_value(&self, req: HttpRequest, db: Data<Arc<DatabaseConnection>>, req_body: Json<Value>) -> HttpResponse {
        HttpResponse::InternalServerError().body("The independent deployment feature is not supported")
    }

    async fn delete_ref_value(&self, req: HttpRequest, db: Data<Arc<DatabaseConnection>>, req_body: Json<Value>) -> HttpResponse {
        HttpResponse::InternalServerError().body("The independent deployment feature is not supported")
    }

    async fn query_ref_value(&self, req: HttpRequest, db: Data<Arc<DatabaseConnection>>) -> HttpResponse {
        HttpResponse::InternalServerError().body("The independent deployment feature is not supported")
    }
}