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

use crate::resource_facade::{Endorsement, Policy, Rv};
use crate::local::proxy::{EndorsementProxy, PolicyProxy, RvProxy};
use actix_web::web;
use ratelimit::Governor;

pub struct LocalRouteConfigurator;

impl LocalRouteConfigurator {
    pub fn new() -> Self {
        Self
    }
}

impl super::register::RouteConfigurator for LocalRouteConfigurator {
    fn register_routes(&self, cfg: &mut web::ServiceConfig, management_governor: Governor) {
        cfg.service(
            web::scope("/policy")
                .wrap(management_governor.clone())
                .route("", web::post().to(|req, db, req_body| {
                    let policy = PolicyProxy::instance().clone();
                    async move { policy.add_policy(req, db, req_body).await }
                }))
                .route("", web::put().to(|req, db, req_body| {
                    let policy = PolicyProxy::instance().clone();
                    async move { policy.update_policy(req, db, req_body).await }
                }))
                .route("", web::delete().to(|req, db, req_body| {
                    let policy = PolicyProxy::instance().clone();
                    async move { policy.delete_policy(req, db, req_body).await }
                }))
                .route("", web::get().to(|req, db| {
                    let policy = PolicyProxy::instance().clone();
                    async move { policy.query_policy(req, db).await}
                })),
        );
        cfg.service(
            web::scope("/cert")
                .wrap(management_governor.clone())
                .route(
                    "",
                    web::get().to(|req, db, req_body| {
                        let endorsement = EndorsementProxy::instance().clone();
                        async move { endorsement.get_certs(db, req, req_body).await }
                    }),
                )
                .route(
                    "",
                    web::post().to(|req, db, req_body| {
                        let endorsement = EndorsementProxy::instance().clone();
                        async move { endorsement.add_cert(db, req, req_body).await }
                    }),
                )
                .route(
                    "",
                    web::put().to(|req, db, req_body| {
                        let endorsement = EndorsementProxy::instance().clone();
                        async move { endorsement.update_cert(db, req, req_body).await }
                    }),
                )
                .route(
                    "",
                    web::delete().to(|req, db, req_body| {
                        let endorsement = EndorsementProxy::instance().clone();
                        async move { endorsement.delete_cert(db, req, req_body).await }
                    }),
                ),
        );
        cfg.service(
            web::scope("/ref_value")
                .wrap(management_governor.clone())
                .route("", web::post().to(|req, db, req_body| {
                    let rv = RvProxy::instance().clone();
                    async move { rv.add_ref_value(req, db, req_body).await }
                }))
                .route("", web::put().to(|req, db, req_body| {
                    let rv = RvProxy::instance().clone();
                    async move { rv.update_ref_value(req, db, req_body).await }
                }))
                .route("", web::delete().to(|req, db, req_body| {
                    let rv = RvProxy::instance().clone();
                    async move { rv.delete_ref_value(req, db, req_body).await }
                }))
                .route("", web::get().to(|req, db| {
                    let rv = RvProxy::instance().clone();
                    async move { rv.query_ref_value(req, db).await}
                })),
        );
    }
}
