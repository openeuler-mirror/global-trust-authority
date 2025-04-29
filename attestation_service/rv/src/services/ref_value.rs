use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use sea_orm::{DatabaseConnection};
use crate::error::ref_value_error::RefValueError;

#[allow(async_fn_in_trait)]
pub trait RefValue {
    /// Adds a new reference value to the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the reference value data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn add_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> Result<HttpResponse, RefValueError>;

    /// Updates an existing reference value in the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the updated reference value data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn update_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> Result<HttpResponse, RefValueError>;

    /// Deletes an existing reference value from the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the reference value identifier
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn delete_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> Result<HttpResponse, RefValueError>;

    /// Queries reference value based on provided parameters.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and query parameters
    /// * `db` - Database connection wrapped in web::Data
    ///
    /// # Returns
    /// * `HttpResponse` - Response containing the query results or error message
    async fn query_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>) -> Result<HttpResponse, RefValueError>;

    async fn verify(measurements: Vec<&str>, user_id: &str, attester_type: &str) -> (bool, Vec<String>);
}