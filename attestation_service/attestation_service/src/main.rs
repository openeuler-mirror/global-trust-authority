mod controllers;
mod middlewares;
mod routes;
mod utils;

use std::env;
use crate::middlewares::filter::default_filter::DefaultFilter;
use crate::routes::routes::configure_user_routes;
use actix_web::{middleware, web, App, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use utils::env_setting_center::{default_not_found_page, get_address, get_https_address};
use ratelimit::{create_challenge_governor, create_management_governor};
use rdb::get_connection;
use crate::utils::env_setting_center::{get_cert_path, get_env_value_or_default, get_key_path, load_env};
use crate::middlewares::mq::create_mq_topics;
use server_config::{
    init_chain::handlers::key_init_handle::KeyManagementInitHandler,
    init_chain::chain::builder::InitChainBuilder,
    init_chain::handlers::plugin_init_handler::PluginInitHandler,
};
use server_config::init_chain::init_db_table_handler::DbTableInitHandler;
use server_config::init_chain::yml_init_handler::ConfigInitHandler;
use server_config::init_chain::logger_init_handler::LoggerInitHandler;
use server_config::init_chain::traits::InitContext;

const MAX_JSON_SIZE_DEFAULT: usize = 10 * 1024 * 1024; // 10MB
const HTTPS_SWITCH_ON: u32 = 1;
const HTTPS_SWITCH_OFF: u32 = 0;

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

    // create topic
    create_mq_topics().await;


    let pool = get_connection().await.clone().unwrap();
    let management_governor = create_management_governor();
    let challenge_governor = create_challenge_governor();
    let server = HttpServer::new(move || {
        let max_json_size = env::var("MAX_JSON_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(MAX_JSON_SIZE_DEFAULT);
        App::new()
            // Add rate limiting middleware
            .app_data(web::Data::new(pool.clone()))
            .app_data(
                web::JsonConfig::default()
                    .limit(max_json_size)
                    .error_handler(|err, _| {  // Enable JSON error handling
                        actix_web::error::ErrorBadRequest(
                            format!("JSON payload too large: {}", err)
                        )
                    })
            )
            .app_data(
                web::FormConfig::default()
                    .limit(max_json_size)
                    .error_handler(|err, _| {  // Enable form error handling
                        actix_web::error::ErrorBadRequest(
                            format!("Form payload too large: {}", err)
                        )
                    })
            )
            .wrap(middleware::Logger::default())
            .wrap(DefaultFilter)
            // .configure(|cfg| configure_user_routes(cfg, create_challenge_governor(), create_management_governor()))
            .configure(|cfg| configure_user_routes(cfg, challenge_governor.clone(), management_governor.clone()))
            .default_service(web::route().to(default_not_found_page))
    })
        // Add TCP layer restriction configuration
        .workers(1)
        .max_connections(50)
        .backlog(0);  // Set the waiting queue to 0 and directly reject new connections

    let https_switch = get_env_value_or_default("HTTPS_SWITCH",HTTPS_SWITCH_OFF);
    let server = if https_switch == HTTPS_SWITCH_ON {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key_file(get_key_path(), SslFiletype::PEM).unwrap();
        builder.set_certificate_chain_file(get_cert_path()).unwrap();
        server.bind_openssl(get_https_address(), builder)?
    } else {
        server.bind(get_address())?
    };

    server.run().await
}