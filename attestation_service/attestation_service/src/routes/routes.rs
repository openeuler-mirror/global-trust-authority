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

use crate::controllers::{token_controller, test_controller, attestation_controller};
use actix_web::web;
use actix_web::web::ServiceConfig;
use resource_provider::routes::register::get_route_configurator;
use resource_provider::routes::register::RouteConfigurator;
use ratelimit::Governor;

/// configure routes
pub fn configure_user_routes(cfg: &mut web::ServiceConfig, challenge_governor:Governor, management_governor:Governor) {
    cfg.service(
        web::scope("/nonce")
            .wrap(challenge_governor.clone())
            .route("/getnonce", web::get().to(test_controller::get_nonce))
    );

    cfg.service(
        web::scope("/user")
            .wrap(management_governor.clone())
            .route("/all", web::get().to(test_controller::get_all_users))
    );
    cfg.service(
        web::scope("/token")
            .wrap(management_governor.clone())
            .route("/verify", web::post().to(token_controller::verify_token)),
    );
    cfg.service(
        web::scope("/challenge")
            .wrap(challenge_governor.clone())
            .route("", web::post().to(attestation_controller::get_nonce)),
    );
    cfg.service(
        web::scope("/attest")
            .wrap(challenge_governor.clone())
            .route("", web::post().to(attestation_controller::attest)),
    );
    register_config_manager_routes(cfg, management_governor);
}

fn register_config_manager_routes(cfg: &mut ServiceConfig, management_governor:Governor) {
    let route_configurator = get_route_configurator();
    route_configurator.register_routes(cfg, management_governor);
}
