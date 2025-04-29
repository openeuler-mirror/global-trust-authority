use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use sea_orm::DatabaseConnection;

#[allow(async_fn_in_trait)]
pub trait Policy {
    /// Adds a new policy to the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the policy data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn add_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse;
    /// Updates an existing policy in the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the updated policy data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn update_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse;
    /// Deletes an existing policy from the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the policy identifier
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn delete_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse;
    /// Queries policies based on provided parameters.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and query parameters
    /// * `db` - Database connection wrapped in web::Data
    ///
    /// # Returns
    /// * `HttpResponse` - Response containing the query results or error message

    async fn query_policy(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>) -> HttpResponse;

    fn test(&self);
}