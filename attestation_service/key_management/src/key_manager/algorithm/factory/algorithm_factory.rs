use crate::key_manager::error::KeyManagerError;
use anyhow::Result;
use mockall::automock;
use once_cell::sync::Lazy;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;
use parking_lot::Mutex;
use std::collections::HashMap;
use common_log::info;
use crate::key_manager::cache::entity::key_pair::KeyPair;
use crate::key_manager::model::PrivateKey;

// factory function
pub fn create_algorithm(algorithm_str: &str) -> Result<Box<dyn KeyAlgorithm>, KeyManagerError> {
    info!("create_algorithm: {}", algorithm_str);
    let parts: Vec<&str> = algorithm_str.split("_").collect();
    let (name, args) = parts
        .split_first()
        .ok_or_else(|| KeyManagerError::new("Empty algorithm string"))?;

    let registry = ALGORITHM_REGISTRY.lock();
    let ctor = registry
        .get(*name)
        .ok_or_else(|| KeyManagerError::new(format!("Algorithm not found: {}", name)))?;
    info!("create_algorithm success: {}", algorithm_str);
    Ok(ctor(args)?)
}

// Global algorithm registry
type AlgorithmConstructor = fn(&[&str]) -> Result<Box<dyn KeyAlgorithm>>;
pub(crate) static ALGORITHM_REGISTRY: Lazy<Mutex<HashMap<&'static str, AlgorithmConstructor>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[automock]
pub trait KeyAlgorithm {
    fn derive_public(&self, private: &PrivateKey) -> Result<KeyPair, KeyManagerError>;
    fn sign(&self, private: &PKey<Private>, data: Vec<u8>) -> Result<Vec<u8>, KeyManagerError>;
    fn verify(
        &self,
        public: &PKey<Public>,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, KeyManagerError>;
}

#[macro_export]
macro_rules! register_algorithm {
    ($name:expr, $ctor:expr) => {
        #[ctor::ctor]
        fn register() {
            $crate::key_manager::algorithm::factory::algorithm_factory::ALGORITHM_REGISTRY
                .lock()
                .insert($name, $ctor);
        }
    };
}