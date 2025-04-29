use std::sync::Arc;
use actix_web::{HttpRequest, HttpResponse};
use actix_web::web::{Data, Json};
use awc::cookie::time::format_description::modifier;
use sea_orm::DatabaseConnection;
use serde_json::Value;
use crate::resource_facade::Policy;

pub struct PolicyImpl;

impl PolicyImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Policy for PolicyImpl {
    fn add_policy(&self, _req: HttpRequest, _db: Data<Arc<DatabaseConnection>>, _req_body: Json<Value>) -> impl std::future::Future<Output = HttpResponse> + Send {
        async move {HttpResponse::InternalServerError().body("The independent deployment feature is not supported")}
    }

    fn update_policy(&self, _req: HttpRequest, _db: Data<Arc<DatabaseConnection>>, _req_body: Json<Value>) -> impl std::future::Future<Output = HttpResponse> + Send {
        async move {HttpResponse::InternalServerError().body("The independent deployment feature is not supported")}
    }

    fn delete_policy(&self, _req: HttpRequest, _db: Data<Arc<DatabaseConnection>>, _req_body: Json<Value>) -> impl std::future::Future<Output = HttpResponse> + Send {
        async move {HttpResponse::InternalServerError().body("The independent deployment feature is not supported")}
    }

    fn query_policy(&self, _req: HttpRequest, _db: Data<Arc<DatabaseConnection>>) -> impl std::future::Future<Output = HttpResponse> + Send {
        async move {HttpResponse::InternalServerError().body("The independent deployment feature is not supported")}
    }

    fn test(&self) {
        println!("Added methods")
    }
}