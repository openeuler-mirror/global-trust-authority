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

use crate::key_manager::error::KeyManagerError;
use crate::key_manager::lifecycle::key_observer::observer_init::register::OBSERVER_REGISTRY;
use crate::key_manager::lifecycle::key_subject::{KeyLifecycle };
use crate::key_manager::lifecycle::key_subject::KeySubject;
use crate::key_manager::restful::key_by_http::DefaultKeyProvider;
use crate::key_manager::restful::KeyProvider;
use lazy_static::lazy_static;
use mockall::automock;
use std::future::Future;
use std::sync::Mutex;
use common_log::info;
use crate::config::YamlConfigLoader;
use crate::key_manager::restful::key_api_client::KeyApiClient;

lazy_static! {
    static ref IS_INITIALIZED: Mutex<bool> = Mutex::new(false);
}

fn set_initialized() {
    let mut flag = IS_INITIALIZED.lock().unwrap();
    *flag = true;
}

 /// Check if already initialized
 /// 
 /// # Returns
 /// 
 /// * `bool` - Whether already initialized
pub fn is_initialized() -> bool {
    *IS_INITIALIZED.lock().unwrap()
}

/**
 * Key initialization interface
 */
#[automock]
pub trait KeyInitialization {
    /**
     * Initialize keys
     *
     * @return Initialization result
     */
    fn initialize(&mut self) -> impl Future<Output = Result<(), KeyManagerError>>;
}

#[derive(Debug)]
pub struct DefaultKeyInitialization {
    default_key_provider: DefaultKeyProvider,
    key_subject: KeySubject,
}

impl DefaultKeyInitialization {
    pub fn new(default_key_provider: DefaultKeyProvider, key_subject: KeySubject) -> DefaultKeyInitialization {
        Self {
            default_key_provider,
            key_subject,
        }
    }
}

/**
 * Initialize the default key. Invoke the vault interface to obtain the full key
 *
 */
impl KeyInitialization for DefaultKeyInitialization {
    async fn initialize(&mut self) -> Result<(), KeyManagerError> {
        // Get the full key rustful -> vault
        let keys = self.default_key_provider
            .get_keys()
            .await
            .map_err(|e| KeyManagerError::new(e.to_string()))?;
        // Key management watcher mode for key rotation
        let key_manager = &mut self.key_subject;
        // load watchers from the registry
        if let Some(registry) = OBSERVER_REGISTRY.get() {
            for observer in registry.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                key_manager.attach(observer.clone());
            }
        }
        key_manager
            .perform_key_rotation(keys)
            .await
            .map_err(|e| KeyManagerError::new(e.to_string()))?;

        set_initialized();

        if !is_initialized() {
            panic!("Key initialization failed");
        }
        info!("Key initialization succeeded");
        Ok(())
    }
}

/// Initialize keys
/// 
/// # Returns
/// 
/// * `Result<(), KeyManagerError>` - The result of the initialization.
pub async fn init_keys() -> Result<(), KeyManagerError> {
    let yaml_config_loader = Box::new(YamlConfigLoader);
    let key_api_client = Box::new(KeyApiClient::new());
    let default_key_provider = DefaultKeyProvider::new(yaml_config_loader, key_api_client);
    let key_subject = KeySubject::new();
    let mut init = DefaultKeyInitialization::new(default_key_provider, key_subject);
    init.initialize().await
}