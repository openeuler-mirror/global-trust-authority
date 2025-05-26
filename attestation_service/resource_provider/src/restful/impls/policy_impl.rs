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