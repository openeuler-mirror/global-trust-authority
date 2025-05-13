use crate::resource_facade::endorsement::Endorsement;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use sea_orm::DatabaseConnection;
use serde_json::Value;
use std::sync::Arc;

pub struct EndorsementImpl;

impl EndorsementImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Endorsement for EndorsementImpl {
    fn get_certs(
        &self,
        _db: Data<Arc<DatabaseConnection>>,
        _query: Query<Value>,
        _req: HttpRequest,
    ) -> impl std::future::Future<Output = HttpResponse> {
        async move { HttpResponse::InternalServerError().body("The independent deployment feature is not supported") }
    }

    fn add_cert(
        &self,
        _db: Data<Arc<DatabaseConnection>>,
        _add_cert: Json<Value>,
        _req: HttpRequest,
    ) -> impl std::future::Future<Output = HttpResponse> {
        async move { HttpResponse::InternalServerError().body("The independent deployment feature is not supported") }
    }

    fn delete_cert(
        &self,
        _db: Data<Arc<DatabaseConnection>>,
        _delete_request: Json<Value>,
        _req: HttpRequest,
    ) -> impl std::future::Future<Output = HttpResponse> {
        async move { HttpResponse::InternalServerError().body("The independent deployment feature is not supported") }
    }

    fn update_cert(
        &self,
        _db: Data<Arc<DatabaseConnection>>,
        _add_cert: Json<Value>,
        _req: HttpRequest,
    ) -> impl std::future::Future<Output = HttpResponse> {
        async move { HttpResponse::InternalServerError().body("The independent deployment feature is not supported") }
    }
}
