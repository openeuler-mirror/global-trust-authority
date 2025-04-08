use actix_web::{App, HttpServer};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use crate::controller::cipher_controller::get_ciphers;
use crate::utils::env_setting_center::{get_cert, get_key, get_port, get_tls, load_env};

pub mod controller;
pub mod key_manager;
pub mod config;
pub mod utils;

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
    load_env();

    let server = HttpServer::new(|| App::new().service(get_ciphers));

    let server = if get_tls() {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        match builder.set_private_key_file(get_key(), SslFiletype::PEM) {
            Ok(_) => (),
            Err(e) => {
                log::error!("{}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
            }
        };
        match builder.set_certificate_chain_file(get_cert()) {
            Ok(_) => (),
            Err(e) => {
                log::error!("{}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
            }
        }
        server.bind_openssl(("0.0.0.0", get_port()), builder)?
    } else {
        server.bind(("0.0.0.0", get_port()))?
    };
    server.run().await
}
