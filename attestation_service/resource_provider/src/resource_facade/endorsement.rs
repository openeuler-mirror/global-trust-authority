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
