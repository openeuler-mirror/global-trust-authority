use std::env;
use actix_web::{App, HttpServer};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use crate::controller::cipher_controller::get_ciphers;

pub mod controller;
pub mod key_manager;
mod config;

fn get_port() -> u16 {
    env::var("KEY_MANAGER_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(8080)
}

fn setup_logger() {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {l} - {m}\n")))
        .build();
    let log_path = "log.log";
    let file_config = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {l} - {m}\n")))
        .build(log_path)
        .unwrap();
    // 构建日志配置
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("file", Box::new(file_config)))
        .build(
            Root::builder()
                .appender("stdout")
                .appender("file")
                .build(LevelFilter::Info),
        )
        .unwrap();
    // 初始化日志系统
    log4rs::init_config(config).unwrap();
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    setup_logger();
    let port = get_port();
    HttpServer::new(|| App::new().service(get_ciphers))
        .bind(("0.0.0.0", port))?
        .run()
        .await
}
