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