/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the
 * Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use common_log::{error, info};
use distributed_lock::Lock as DistributedLock;
use mockall::automock;
use rdb::get_connection;
use sea_orm::TransactionTrait;

use crate::config::{ConfigLoader, YamlConfigLoader};
use crate::key_manager::algorithm::create_algorithm;
use crate::key_manager::cache::store::KeyStore;
use crate::key_manager::error::KeyManagerError;
use crate::key_manager::lifecycle::key_observer::observer_init::register::OBSERVER_REGISTRY;
use crate::key_manager::lifecycle::key_observer::KeyLifecycleObserver;
use crate::key_manager::model::{KeyVersionModel, VaultResponse, Version};
use crate::key_manager::orm::entity::key_manager_key_version::{get_current_key_version, update_key_version};

#[derive(Debug)]
pub struct KeySubject {
    observers: Vec<Arc<dyn KeyLifecycleObserver + Send + Sync>>,
    lock: KeyRotationLock,
}

impl KeySubject {
    pub fn new() -> Self {
        KeySubject { observers: Vec::new(), lock: KeyRotationLock::new() }
    }

    // Add watchers
    pub fn attach(&mut self, observer: Arc<dyn KeyLifecycleObserver + Send + Sync>) {
        self.observers.push(observer);
    }

    // Inform all observers
    async fn notify_observers(&self, key_version: &str) -> Result<(), KeyManagerError> {
        let registry = OBSERVER_REGISTRY.get().unwrap();
        let observers = registry.lock().unwrap();
        let db_connection = get_connection().await.unwrap();
        // Open a transaction
        let tx = db_connection.begin().await.unwrap();
        let tx_arc = Arc::new(tx);
        let mut tx_holder = Some(tx_arc);
        for observer in observers.iter() {
            info!("KeySubject: Notifying observer: ");
            let current_tx = Arc::clone(tx_holder.as_ref().unwrap());
            match observer.signature_update(key_version, current_tx).await {
                Ok(_) => (),
                Err(_e) => {
                    error!("KeySubject: Failed to notify observers");
                    // Roll back the transaction
                    if let Some(tx_arc) = tx_holder.take() {
                        match Arc::try_unwrap(tx_arc) {
                            Ok(_tx) => (),
                            Err(_e) => {
                                return Err(KeyManagerError::new(
                                    "Unable to rollback the transaction: there are unreleased references.".to_string(),
                                ));
                            },
                        }
                    }
                    return Err(KeyManagerError::new("Failed to notify observers".to_string()));
                },
            }
        }
        // Need to extract the original object from Arc when committing a transaction
        if let Some(tx_arc) = tx_holder.take() {
            match Arc::try_unwrap(tx_arc) {
                Ok(tx) => tx.commit().await?,
                Err(_) => {
                    return Err(KeyManagerError::new(
                        "Unable to submit the transaction: there are unreleased references.".to_string(),
                    ))
                },
            }
        }
        info!("KeySubject: Notified observers");
        Ok(())
    }
}

#[automock]
pub trait KeyLifecycle {
    /**
     * Key Rotation
     *
     * @param vault_response Full key data
     * @return Initialization result
     */
    fn perform_key_rotation(
        &self,
        vault_response: VaultResponse,
    ) -> impl std::future::Future<Output = Result<(), KeyManagerError>>;

    /**
     * Generate Key Pair
     *
     * @param vault_response Full key data
     * @param db_version Database key version
     * @return Initialization result
     */
    fn generate_key_pair(
        vault_response: &VaultResponse,
        db_version: &Version,
    ) -> impl std::future::Future<Output = Result<(), KeyManagerError>>;
}

impl KeyLifecycle for KeySubject {
    fn perform_key_rotation(
        &self,
        vault_response: VaultResponse,
    ) -> impl std::future::Future<Output = Result<(), KeyManagerError>> {
        async move {
            info!("KeySubject: Performing key rotation...");
            // Check the database key version
            let db_version = get_current_key_version().await.unwrap_or_else(|e| {
                info!("No current version found, using v1 as default: {}", e);
                Version::new("v1")
            });
            info!("Database key version: {}", db_version);
            // Derived key database version v1: Query the latest key v5: Derived key range i
            // v1-v5
            Self::generate_key_pair(&vault_response, &db_version).await?;

            let max_version = vault_response.find_max_version().unwrap();
            info!("Max version: {}", max_version);
            if db_version > max_version {
                info!("db_version is large than max_version, db_version: {}, max_version: {}", db_version, max_version);
                panic!("The key data version is incorrect, and the service failed to start");
            }
            let key_store = KeyStore::global();
            let latest_version = key_store.get_latest_version("TSK").unwrap();
            println!("KeySubject: latest_version: {}", latest_version);
            // Get distributed locks
            self.lock.acquire()?;
            info!("KeySubject: Acquired key rotation lock");
            // Check the database version again
            let db_version = get_current_key_version().await.unwrap_or_else(|e| {
                info!("No current version found, using v1 as default: {}", e);
                Version::new("v1")
            });
            info!("KeySubject: Database key version: {}", db_version);
            // Whether rotation is required
            let need_rotation = db_version < max_version;
            if need_rotation {
                // key rotation
                info!("KeySubject: Key rotation is needed. Notifying observers...");
                let max_version = max_version.to_string();
                let notify_result = self.notify_observers(max_version.as_str());
                if notify_result.await.is_err() {
                    error!("KeySubject: Failed to notify observers");
                    // Roll back the transaction
                    return Err(KeyManagerError::new("Failed to notify observers".to_string()));
                }
                info!("max_version.to_string(): {}", max_version.to_string());
                // Update the database key version
                // Open a transaction
                let db_connection = get_connection().await.unwrap();
                let tx = db_connection.begin().await.unwrap();
                update_key_version(max_version.to_string(), &tx).await?;
                tx.commit().await?;
            }
            info!("KeySubject: Key rotation successfully completed");
            Ok(())
        }
    }

    fn generate_key_pair(
        vault_response: &VaultResponse,
        db_version: &Version,
    ) -> impl std::future::Future<Output = Result<(), KeyManagerError>> {
        async move {
            info!("KeySubject: Generating key pair...");
            let store = KeyStore::global();
            let process = |(key_type, keys): (&str, &Vec<KeyVersionModel>)| -> Result<(), KeyManagerError> {
                let keys = keys.iter().filter(|v| &v.version >= db_version);

                keys.for_each(|v| {
                    init_store(&store, key_type, v).unwrap();
                    info!("KeySubject: Initialized store for key type: {}", key_type);
                });
                Ok(())
            };
            let key_vec = || {
                let yaml = YamlConfigLoader;
                let config = yaml.load_config().expect("can't load YamlConfig");
                let mut keys = Vec::new();

                // Add elements based on conditions
                if config.is_require_sign() {
                    keys.push(("FSK", &vault_response.fsk));
                }
                keys.extend_from_slice(&[("NSK", &vault_response.nsk), ("TSK", &vault_response.tsk)]);

                keys
            };
            key_vec().into_iter().try_for_each(process)
        }
    }
}

fn init_store(store: &KeyStore, key_type: &str, v: &KeyVersionModel) -> Result<(), KeyManagerError> {
    info!("KeySubject: Initializing store for key type: {}", key_type);
    let key_pair = create_algorithm(&v.algorithm).and_then(|alg| {
        alg.derive_public(&v.private_key).or_else(|_| {
            panic!("Failed to derive public key for key type: {}", key_type);
        })
    })?;
    store.insert(key_type, &v.version, key_pair)
}

#[derive(Debug)]
struct KeyRotationLock {
    lock: DistributedLock,
}

impl KeyRotationLock {
    pub fn new() -> Self {
        Self { lock: DistributedLock::new("key_rotation_lock", "key_rotation_lock", 30, 1).unwrap() }
    }

    pub fn acquire(&self) -> Result<(), KeyManagerError> {
        loop {
            match self.lock.acquire() {
                Ok(true) => {
                    info!("KeySubject: Acquired key rotation lock");
                    return Ok(());
                },
                Ok(false) => {
                    info!("Failed to acquire key rotation lock, retrying...");
                    thread::sleep(Duration::from_secs(5));
                    continue;
                },
                Err(e) => {
                    error!("Failed to acquire key rotation lock: {}", e);
                    return Err(KeyManagerError::new(e.to_string()));
                },
            }
        }
    }
}

impl Drop for KeyRotationLock {
    fn drop(&mut self) {
        if let Err(e) = self.lock.release() {
            error!("Failed to release key rotation lock: {}", e);
        }
        info!("KeySubject: Dropped the key rotation lock");
    }
}
