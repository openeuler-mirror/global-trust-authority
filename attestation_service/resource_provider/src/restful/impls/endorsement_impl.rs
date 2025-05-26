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
