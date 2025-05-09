// src/key_api_client/mod.rs

use crate::key_manager::error::KeyManagerError;
use crate::key_manager::model::VaultResponse;
use reqwest::{Certificate, Client, ClientBuilder, Identity};
use std::fmt;
use std::fmt::Debug;
use std::fs::read;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

pub struct KeyApiClient {
    client: Client,
}

impl fmt::Debug for KeyApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyApiClient").field("client", &"reqwest::Client").finish()
    }
}

impl KeyApiClient {
    pub fn new() -> Self {
        Self { client: get_https_client() }
    }

    pub fn get_keys(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<VaultResponse, Box<KeyManagerError>>>>> {
        let client = self.client.clone();
        let url = url.to_string();
        dbg!(&url);
        Box::pin(async move {
            let mut response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| KeyManagerError::new(format!("Failed to send GET request: {}", e)))?;

            let key_response: VaultResponse =
                response.json().await.map_err(|e| KeyManagerError::new(format!("Failed to parse JSON: {}", e)))?;

            Ok(key_response)
        })
    }
}

fn get_https_client() -> Client {
    let current_dir = std::env::current_dir().unwrap();
    let cert_path = current_dir.clone().join("/tmp/certs/ra_client_cert.pem");
    let key_path = current_dir.clone().join("/tmp/certs/ra_client_key.pem");
    let cert_path = Path::new(&cert_path);
    let key_path = Path::new(&key_path);
    let cert = read(cert_path)
        .map_err(|e| {
            KeyManagerError::new(format!(
                "Failed to read client cert:{}", e
            ))
        })
        .unwrap();
    let key = read(key_path).map_err(|e| KeyManagerError::new(format!("Failed to read client key: {}", e))).unwrap();
    // 2. Strictly merge PEM data
    let mut identity_data = cert.clone();
    identity_data.extend_from_slice(b"\n");
    identity_data.extend_from_slice(&key);
    // 3. create Identity
    let identity =
        Identity::from_pem(&identity_data).map_err(|e| KeyManagerError::new(format!("Identity error: {}", e))).unwrap();
    // 3. Load the root certificate of KeyManager (used to verify the server)
    let ca_cert = read(current_dir.join("/tmp/certs/km_cert.pem").to_str().unwrap())
        .map_err(|e| KeyManagerError::new(format!("Failed to read CA cert: {}", e)))
        .unwrap();
    let ca_cert = Certificate::from_pem(&ca_cert)
        .map_err(|e| KeyManagerError::new(format!("Failed to parse CA cert: {}", e)))
        .unwrap();
    let client_builder = ClientBuilder::new()
        .use_rustls_tls()
        .identity(identity)
        .add_root_certificate(ca_cert);
    #[cfg(debug_assertions)]
    {
        client_builder.danger_accept_invalid_certs(true).build()
            .map_err(|e| KeyManagerError::new(format!("Failed to build client: {}", e)))
            .unwrap()
    }
    #[cfg(not(debug_assertions))]
    {
        client_builder.danger_accept_invalid_hostnames(false).build()
            .map_err(|e| KeyManagerError::new(format!("Failed to build client: {}", e)))
            .unwrap()
    }
}

pub trait KeyApiClientTrait: Debug {
    fn get_keys(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<VaultResponse, Box<KeyManagerError>>>>>;
}

impl KeyApiClientTrait for KeyApiClient {
    fn get_keys(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<VaultResponse, Box<KeyManagerError>>>>> {
        Box::pin(self.get_keys(url))
    }
}