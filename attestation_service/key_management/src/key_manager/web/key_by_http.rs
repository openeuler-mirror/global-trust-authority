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