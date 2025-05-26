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

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::sync::Arc;
use actix_web::{App, HttpServer};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use key_managerd::controller::cipher_controller::get_ciphers;
use key_managerd::key_manager::secret_manager_factory::{SecretManagerFactory, SecretManagerType};
use key_managerd::utils::env_setting_center::{load_env, Environment};
use key_managerd::utils::errors::AppError;
use key_managerd::utils::logger::init_logger;

fn load_certs(path: &str) -> Result<Vec<Certificate>, AppError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            log::error!("load file error, msg:{}", err);
            return Err(AppError::FileLoadError(err.to_string()))
        }
    };
    let mut reader = BufReader::new(file);
    certs(&mut reader)
        .map_err(|err| {
            log::error!("load cert error, msg:{}", err);
            AppError::CertLoadError(err.to_string())
        })
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_private_key(path: &str) -> Result<PrivateKey, AppError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => return Err(AppError::FileLoadError(err.to_string()))
    };
    let mut reader = BufReader::new(file);
    let mut keys = pkcs8_private_keys(&mut reader)
        .map_err(|err| {
            log::error!("load private key error, msg:{}", err);
            AppError::CertLoadError(err.to_string())
        })?;
    if keys.len() != 1 {
        log::error!("private key count is error, count {}", keys.len());
        return Err(AppError::CertLoadError(format!("private key count is error, count {}",  keys.len())));
    }
    Ok(PrivateKey(keys.remove(0)))
}

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
    init_logger(true).expect("failed to init logger");
    let config = Environment::global();
    let mut server = HttpServer::new(|| App::new()
        .service(get_ciphers));
    let mut root_store = rustls::RootCertStore::empty();
    let root_ca_certs = load_certs(&config.root_ca_cert).map_err(|err| io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
    root_ca_certs.iter().try_for_each(|cert| {
        root_store.add(cert).map_err(|err| {
            log::error!("load ca cert error: {}", err);
            io::Error::new(std::io::ErrorKind::Other, err.to_string())
        })
    })?;
    let client_auth = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
    let builder = match ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(client_auth))
        .with_single_cert(
            load_certs(&config.cert).map_err(|err| io::Error::new(std::io::ErrorKind::Other, err.to_string()))?,
            load_private_key(&config.private_key).map_err(|err| io::Error::new(std::io::ErrorKind::Other, err.to_string()))?,
        ) {
        Ok(server) => server,
        Err(err) =>  {
            log::error!("server config error, message: {}", err);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err.to_string()));
        }
    };
    server = server.bind_rustls_021(("0.0.0.0", config.port), builder)?;
    match SecretManagerFactory::create_manager(SecretManagerType::OpenBao).init_system() {
        Ok(_) => {},
        Err(err) => {
            log::error!("{:?} init config error: {}", SecretManagerType::OpenBao, err);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err.to_string()));
        }
    }
    server.run().await
}
