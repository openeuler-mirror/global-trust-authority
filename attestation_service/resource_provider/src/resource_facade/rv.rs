/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse};
use sea_orm::DatabaseConnection;

#[allow(async_fn_in_trait)]
pub trait Rv{
    /// Adds a new reference value to the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the reference value data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn add_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse;
    /// Updates an existing reference value in the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the updated reference value data
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn update_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse;
    /// Deletes an existing reference value from the system.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and context information
    /// * `db` - Database connection wrapped in web::Data
    /// * `req_body` - JSON payload containing the reference value identifier
    ///
    /// # Returns
    /// * `HttpResponse` - Response indicating success or failure of the operation
    async fn delete_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>, req_body: web::Json<serde_json::Value>) -> HttpResponse;
    /// Queries reference value based on provided parameters.
    ///
    /// # Parameters
    /// * `req` - The HTTP request containing authentication and query parameters
    /// * `db` - Database connection wrapped in web::Data
    ///
    /// # Returns
    /// * `HttpResponse` - Response containing the query results or error message
    async fn query_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>) -> HttpResponse;
}