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

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

use once_cell::sync::OnceCell;

use crate::key_manager::cache::entity::key_pair::KeyPair;
use crate::key_manager::error::KeyManagerError;

type VersionMap = Arc<RwLock<HashMap<String, KeyPair>>>;

#[derive(Debug)]
pub struct KeyStore {
    pub(crate) inner: HashMap<String, VersionMap>,
    pub(crate) latest_versions: HashMap<String, OnceCell<String>>,
}

// implementing thread safety tags
unsafe impl Send for KeyStore {
}
unsafe impl Sync for KeyStore {
}

impl KeyStore {
    pub fn global() -> &'static Self {
        static INSTANCE: OnceCell<KeyStore> = OnceCell::new();
        INSTANCE.get_or_init(|| {
            let mut map = HashMap::new();
            for key_type in ["FSK", "NSK", "TSK"] {
                map.insert(key_type.to_string(), Arc::new(RwLock::new(HashMap::new())));
            }
            let latest_versions = HashMap::from([
                ("FSK".to_string(), OnceCell::new()),
                ("NSK".to_string(), OnceCell::new()),
                ("TSK".to_string(), OnceCell::new()),
            ]);
            Self { inner: map, latest_versions }
        })
    }

    pub fn insert(&self, key_type: &str, version: &str, key_pair: KeyPair) -> Result<(), KeyManagerError> {
        let versions = self.inner.get(key_type).ok_or(KeyManagerError::new("Key type not found"))?;

        let mut versions = versions.write().unwrap();
        if versions.contains_key(version) {
            return Err(KeyManagerError::new("Version already exists"));
        }

        versions.insert(version.to_string(), key_pair);
        Ok(())
    }

    pub fn get(&self, key_type: &str, version: &str) -> Option<KeyPair> {
        let versions: &Arc<RwLock<HashMap<String, KeyPair>>> = self.inner.get(key_type)?;
        let binding = versions.read().unwrap();
        let key_pair: &KeyPair = binding.get(version)?;
        Some(key_pair.clone())
    }

    pub fn list_versions(&self) -> Vec<String> {
        self.inner
            .values()
            .flat_map(|v| {
                let versions = v.read().unwrap();
                versions.clone().keys().map(|v| v.to_string()).collect::<Vec<String>>()
            })
            .collect()
    }

    pub fn get_latest_version(&self, key_type: &str) -> Option<&str> {
        let latest_version = self.latest_versions.get(key_type)?.get_or_init(|| {
            let versions = self.inner.get(key_type).unwrap();
            let versions = versions.read().unwrap();

            versions
                .keys()
                .filter_map(|v| v.strip_prefix('v').and_then(|s| s.parse::<u32>().ok()).map(|n| (n, v.as_str())))
                .max_by_key(|&(n, _)| n)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        });
        Some(latest_version)
    }
}

#[allow(warnings)]
mod tests {

    use openssl::rsa::Rsa;

    use super::*;

    #[test]
    fn key_store() {
        let store = KeyStore::global();
        let rsa = Rsa::generate(2048).unwrap();
        store
            .insert(
                "FSK",
                "v1",
                KeyPair {
                    cached_private: OnceCell::new(),
                    cached_public: OnceCell::new(),
                    private_bytes: rsa.private_key_to_pem().unwrap(),
                    public_bytes: rsa.public_key_to_pem().unwrap(),
                    algorithm: "RS256".to_string(),
                },
            )
            .unwrap();
        let result = store.get("FSK", "v1").unwrap();
        assert_eq!(result.public_key().size(), 256);
    }
}
