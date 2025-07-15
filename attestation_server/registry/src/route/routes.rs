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
use actix_web::web;
use ratelimit::Governor;
use crate::controller::register_controller;
use crate::controller::register_controller::register;

pub fn configure_register_routes(cfg: &mut web::ServiceConfig, register_governor:Governor) {
    cfg.service(
        web::scope("/registry")
            .wrap(register_governor.clone())
            .route("", web::post().to(|req, db| {
                register(req, db)
            }))
            .route("", web::get().to(register_controller::register)),
    );
}