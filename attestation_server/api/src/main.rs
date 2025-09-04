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

mod controllers;
mod middlewares;
mod routes;
mod utils;

use crate::middlewares::mq::check_mq_topics;
use crate::routes::routes::configure_user_routes;
use crate::utils::env_setting_center::{
    get_cert_path, get_env_by_key, get_env_value_or_default, get_key_path, load_env,
};
use actix_web::body::BoxBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse};
use actix_web::{middleware, web, App, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use ratelimit::{create_challenge_governor, create_management_governor, create_register_governor};
use rdb::get_connection;
use registry::filter::{AuthFilter, APIKEY_ENABLE};
use registry::route::routes::configure_register_routes;
use server_config::init_chain::init_db_table_handler::DbTableInitHandler;
use server_config::init_chain::logger_init_handler::LoggerInitHandler;
use server_config::init_chain::traits::InitContext;
use server_config::init_chain::yml_init_handler::ConfigInitHandler;
use server_config::{
    init_chain::chain::builder::InitChainBuilder, init_chain::handlers::key_init_handle::KeyManagementInitHandler,
    init_chain::handlers::plugin_init_handler::PluginInitHandler,
};
use std::env;
use std::future::Future;
use utils::env_setting_center::{default_not_found_page, get_address, get_https_address};

const MAX_JSON_SIZE_DEFAULT: usize = 100 * 1024 * 1024; // 100MB
const HTTPS_SWITCH_ON: u32 = 1;
const HTTPS_SWITCH_OFF: u32 = 0;
const USER_ID: &str = "User-Id";
const USER_ID_MAX_LENGTH: usize = 36;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Program started!");
    // load env
    load_env();
    let chain = InitChainBuilder::new()
        .add_handler(LoggerInitHandler::new())
        .add_handler(ConfigInitHandler::new())
        .add_handler(DbTableInitHandler::new())
        .add_handler(KeyManagementInitHandler::new())
        .add_handler(PluginInitHandler::new())
        .build();

    chain.execute(&mut InitContext::new()).await.unwrap();

    // check topic
    check_mq_topics().await;

    let pool = get_connection().await.clone().unwrap();
    let management_governor = create_management_governor();
    let challenge_governor = create_challenge_governor();
    let register_governor = create_register_governor();
    let server = HttpServer::new(move || {
        let max_json_size =
            env::var("MAX_JSON_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(MAX_JSON_SIZE_DEFAULT);
        App::new()
            // Add rate limiting middleware
            .service(
                web::scope("/global-trust-authority/service/v1")
                    .app_data(web::Data::new(pool.clone()))
                    .app_data(web::JsonConfig::default().limit(max_json_size).error_handler(|err, _| {
                        // Enable JSON error handling
                        actix_web::error::ErrorBadRequest(format!("JSON payload too large: {}", err))
                    }))
                    .app_data(web::FormConfig::default().limit(max_json_size).error_handler(|err, _| {
                        // Enable form error handling
                        actix_web::error::ErrorBadRequest(format!("Form payload too large: {}", err))
                    }))
                    .wrap_fn(|req, srv| validate_user_id_header(req, srv))
                    .wrap(middleware::Logger::default())
                    .wrap(AuthFilter)
                    .configure(|cfg| {
                        configure_user_routes(cfg, challenge_governor.clone(), management_governor.clone());
                        if *APIKEY_ENABLE {
                            configure_register_routes(cfg, register_governor.clone());
                        }
                    }),
            )
            .default_service(web::route().to(default_not_found_page))
    })
    // Add TCP layer restriction configuration
    .workers(1)
    .max_connections(50)
    .backlog(0); // Set the waiting queue to 0 and directly reject new connections

    let https_switch = get_env_value_or_default("HTTPS_SWITCH", HTTPS_SWITCH_OFF);
    let server = if https_switch == HTTPS_SWITCH_ON {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key_file(get_key_path(), SslFiletype::PEM).unwrap();
        builder.set_certificate_chain_file(get_cert_path()).unwrap();
        // Set the certificate verification mode to require client certificate verification
        builder.set_verify(openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        builder.set_ca_file(get_env_by_key("CA_CERT_PATH".to_string())).unwrap();
        server.bind_openssl(get_https_address(), builder)?
    } else {
        server.bind(get_address())?
    };

    server.run().await
}

fn validate_user_id_header(
    req: ServiceRequest,
    srv: &impl Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = actix_web::Error>,
) -> impl Future<Output = Result<ServiceResponse<BoxBody>, actix_web::Error>> {
    let is_valid =
        req.headers().get(USER_ID).map(|id| !id.is_empty() && id.len() <= USER_ID_MAX_LENGTH).unwrap_or(false);
    let is_register = req.path().ends_with("register");
    let fut = srv.call(req);
    async move {
        if !is_valid && !is_register{
            Err(actix_web::error::ErrorBadRequest("User-Id header is required and must be 1-36 characters"))
        } else {
            fut.await
        }
    }
}
