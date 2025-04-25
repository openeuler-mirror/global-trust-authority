use actix_web::{App, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use key_managerd::controller::cipher_controller::get_ciphers;
use key_managerd::key_manager::secret_manager_factory::{SecretManagerFactory, SecretManagerType};
use key_managerd::utils::env_setting_center::{load_env, Environment};
use key_managerd::utils::logger::init_logger;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    load_env().expect("failed to load .env file");
    match Environment::check() {
        Ok(_) => {}
        Err(err) => {
            log::error!("load env config error, message: {}", err);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err.to_string()));
        }
    }
    let config = Environment::global();
    init_logger(true).expect("failed to init logger");
    let server = HttpServer::new(|| App::new()
        .service(get_ciphers));
    let server = if config.tls {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        match builder.set_private_key_file(&config.tls_key, SslFiletype::PEM) {
            Ok(_) => (),
            Err(e) => {
                log::error!("private key file set failed, message: {}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
            }
        };
        match builder.set_certificate_chain_file(&config.tls_cert) {
            Ok(_) => (),
            Err(e) => {
                log::error!("cert chain file set failed, message: {}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
            }
        }
        builder.set_verify(SslVerifyMode::PEER |  SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        match builder.set_ca_file(&config.ca_cert) {
            Ok(_) => {}
            Err(e) => {
                log::error!("ca cert file set failed, message: {}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
            }
        };
        server.bind_openssl(("0.0.0.0", config.port), builder)?
    } else {
        server.bind(("0.0.0.0", config.port))?
    };
    match SecretManagerFactory::create_manager(SecretManagerType::OpenBao).init_system() {
        Ok(_) => {},
        Err(err) => {
            log::error!("{:?} init config error: {}", SecretManagerType::OpenBao, err);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err.to_string()));
        }
    }
    server.run().await
}
