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

use crate::resource_facade::Rv;
use actix_web::{web, HttpRequest, HttpResponse};
use common_log::info;
use rv::services::rv_factory::RvFactory;
use rv::services::rv_trait::RefValueTrait;
use sea_orm::DatabaseConnection;
use std::sync::{Arc, OnceLock};

pub struct RvProxy;

static RV_PROXY_INSTANCE: OnceLock<Arc<RvProxy>> = OnceLock::new();

impl RvProxy {
    pub(crate) fn new() -> Self {
        Self
    }

    pub fn instance() -> &'static Arc<RvProxy> {
        RV_PROXY_INSTANCE.get_or_init(|| Arc::new(RvProxy::new()))
    }
}

impl Rv for RvProxy {
    async fn add_ref_value(
        &self,
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        req_body: web::Json<serde_json::Value>,
    ) -> HttpResponse {
        let rv = RvFactory::create_ref_value();
        info!("Received request to add ref_value");
        match rv.add_ref_value(req, db, req_body).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }

    async fn update_ref_value(
        &self,
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        req_body: web::Json<serde_json::Value>,
    ) -> HttpResponse {
        let rv = RvFactory::create_ref_value();
        info!("Received request to update ref_value");
        match rv.update_ref_value(req, db, req_body).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }

    async fn delete_ref_value(
        &self,
        req: HttpRequest,
        db: web::Data<Arc<DatabaseConnection>>,
        req_body: web::Json<serde_json::Value>,
    ) -> HttpResponse {
        let rv = RvFactory::create_ref_value();
        info!("Received request to delete ref_value");
        match rv.delete_ref_value(req, db, req_body).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }

    async fn query_ref_value(&self, req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>) -> HttpResponse {
        info!("Received request to query ref_value");
        let rv = RvFactory::create_ref_value();
        match rv.query_ref_value(req, db).await {
            Ok(res) => {
                res
            }
            Err(err) => {
                HttpResponse::build(err.status_code())
                    .json(serde_json::json!({ "message": err.message() }))
            }
        }
    }
}
