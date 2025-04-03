use std::env;
use actix_web::{App, HttpServer};
use crate::controller::cipher_controller::get_ciphers;

pub mod controller;
pub mod key_manager;

fn get_port() -> u16 {
    env::var("KEY_MANAGER_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(8080)
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = get_port();
    HttpServer::new(|| App::new().service(get_ciphers))
        .bind(("0.0.0.0", port))?
        .run()
        .await
}
