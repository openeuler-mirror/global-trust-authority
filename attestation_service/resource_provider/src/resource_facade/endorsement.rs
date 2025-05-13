use actix_web::{web, HttpRequest, HttpResponse};
use sea_orm::DatabaseConnection;
use serde_json::Value;
use std::sync::Arc;

#[allow(async_fn_in_trait)]
pub trait Endorsement {
    async fn get_certs(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        query: web::Query<Value>,
        req: HttpRequest,
    ) -> HttpResponse;

    async fn add_cert(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        add_cert: web::Json<Value>,
        req: HttpRequest,
    ) -> HttpResponse;

    async fn delete_cert(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        delete_request: web::Json<Value>,
        req: HttpRequest,
    ) -> HttpResponse;

    async fn update_cert(
        &self,
        db: web::Data<Arc<DatabaseConnection>>,
        add_cert: web::Json<Value>,
        req: HttpRequest,
    ) -> HttpResponse;
}
