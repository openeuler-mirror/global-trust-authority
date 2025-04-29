// src/key_api_client/mod.rs

use std::fmt;
use awc::Client;
use crate::key_manager::error::KeyManagerError;
use crate::key_manager::model::VaultResponse;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use mockall::automock;
pub struct KeyApiClient {
    client: Client,
}

impl fmt::Debug for KeyApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyApiClient")
            .field("client", &"awc::Client")
            .finish()
    }
}

impl KeyApiClient {
    pub fn new() -> Self {
        Self {
            client: Client::default(),
        }
    }

    pub fn get_keys(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<VaultResponse, Box<KeyManagerError>>>>> {
        let client = self.client.clone();
        let url = url.to_string();

        Box::pin(async move {
            let mut response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| KeyManagerError::new(format!("Failed to send GET request: {}", e)))?;

            let key_response: VaultResponse = response.json().await.map_err(|e| {
                KeyManagerError::new(format!("Failed to parse JSON: {}", e))
            })?;

            Ok(key_response)
        })
    }
}

#[automock]
pub trait KeyApiClientTrait: Debug {
    fn get_keys(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<VaultResponse, Box<KeyManagerError>>>>>;
}


impl KeyApiClientTrait for KeyApiClient {
    fn get_keys(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<VaultResponse, Box<KeyManagerError>>>>> {
        Box::pin(self.get_keys(url))
    }
}