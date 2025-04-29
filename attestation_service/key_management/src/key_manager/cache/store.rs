use crate::key_manager::cache::entity::key_pair::KeyPair;
use crate::key_manager::error::KeyManagerError;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

type VersionMap = Arc<RwLock<HashMap<String, KeyPair>>>;

#[derive(Debug)]
pub struct KeyStore {
    pub(crate) inner: HashMap<String, VersionMap>,
    pub(crate) latest_version: OnceCell<String>,
}

// implementing thread safety tags
unsafe impl Send for KeyStore {}
unsafe impl Sync for KeyStore {}

impl KeyStore {
    pub fn global() -> &'static Self {
        static INSTANCE: OnceCell<KeyStore> = OnceCell::new();
        INSTANCE.get_or_init(|| {
            let mut map = HashMap::new();
            for key_type in ["FSK", "NSK", "TSK"] {
                map.insert(key_type.to_string(), Arc::new(RwLock::new(HashMap::new())));
            }
            Self {
                inner: map,
                latest_version: OnceCell::new(),
            }
        })
    }

    pub fn insert(
        &self,
        key_type: &str,
        version: &str,
        key_pair: KeyPair,
    ) -> Result<(), KeyManagerError> {
        let versions = self
            .inner
            .get(key_type)
            .ok_or(KeyManagerError::new("Key type not found"))?;

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

    pub fn get_latest_version(&self) -> Option<&str> {
        let latest_version = self.latest_version.get_or_init(|| {
            self.list_versions()
                .into_iter()
                .filter_map(|v| {
                    v.strip_prefix('v')
                        .and_then(|s| s.parse::<u32>().ok())
                        .map(|n| (n, v))
                })
                .max_by_key(|&(n, _)| n)
                .map(|(_, v)| v)
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
        store.insert("FSK", "v1", KeyPair {
            cached_private: OnceCell::new(),
            cached_public: OnceCell::new(),
            private_bytes: rsa.private_key_to_pem().unwrap(),
            public_bytes: rsa.public_key_to_pem().unwrap(),
            algorithm: "RS256".to_string(),
        }).unwrap();
        let result = store.get("FSK", "v1").unwrap();
        assert_eq!(result.public_key().size(), 256);
    }
}