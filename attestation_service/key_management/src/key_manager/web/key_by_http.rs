use std::fmt::Debug;
use std::future::Future;
use crate::config::ConfigLoader;
use crate::key_manager::error::KeyManagerError;
use crate::key_manager::model::VaultResponse;
use mockall::automock;
use common_log::info;
use crate::key_manager::web::key_api_client::KeyApiClientTrait;

#[automock]
pub trait KeyProvider {
    fn get_keys(&self) -> impl Future<Output = Result<VaultResponse, Box<KeyManagerError>>>;
}

#[derive(Debug)]
pub struct DefaultKeyProvider {
    pub config_loader: Box<dyn ConfigLoader>,
    pub key_api_client: Box<dyn KeyApiClientTrait>,
}

impl DefaultKeyProvider {
    pub fn new(
        config_loader: Box<dyn ConfigLoader>,
        key_api_client: Box<dyn KeyApiClientTrait>,
    ) -> Self {
        Self {
            config_loader,
            key_api_client,
        }
    }
}

impl KeyProvider for DefaultKeyProvider {
    fn get_keys(&self) -> impl Future<Output = Result<VaultResponse, Box<KeyManagerError>>> {
        let key_api_client = &self.key_api_client;
        let config_loader = &self.config_loader;

        async move {
            let config = config_loader.load_config().unwrap();
            let vault_get_key_url = config.vault_get_key_url();
            info!("Vault get key url: {}", &vault_get_key_url);

            info!("Vault get key client: ");
            let response = key_api_client.get_keys(&vault_get_key_url).await?;
            Ok(response)
        }
    }
}