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

/// factory function
/// 
/// # Arguments
/// 
/// * `algorithm_str` - algorithm string
/// 
/// # Returns
/// 
/// * `Result<Box<dyn KeyAlgorithm>, KeyManagerError>` - Success or error
/// 
/// # Errors
/// 
/// * `KeyManagerError` - If the algorithm is not supported. 
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
    /// Generate a key pair
    /// 
    /// # Arguments
    /// 
    /// * `args` - arguments
    /// 
    /// # Returns
    /// 
    /// * `Result<KeyPair, KeyManagerError>` - Success or error
    /// 
    /// # Errors
    /// 
    /// * `KeyManagerError` - If the algorithm is not supported.
    fn derive_public(&self, private: &PrivateKey) -> Result<KeyPair, KeyManagerError>;

    /// Sign data
    ///
    /// # Arguments
    /// 
    /// * `private` - private key
    /// * `data` - data to sign
    /// 
    /// # Returns
    /// 
    /// * `Result<Vec<u8>, KeyManagerError>` - Success or error
    /// 
    /// # Errors
    /// 
    /// * `KeyManagerError` - If the algorithm is not supported.
    fn sign(&self, private: &PKey<Private>, data: Vec<u8>) -> Result<Vec<u8>, KeyManagerError>;

    /// Verify signature
    ///
    /// # Arguments
    /// 
    /// * `public` - public key
    /// * `data` - data to verify
    /// * `signature` - signature to verify
    /// 
    /// # Returns
    /// 
    /// * `Result<bool, KeyManagerError>` - Success or error
    /// 
    /// # Errors
    /// 
    /// * `KeyManagerError` - If the algorithm is not supported.
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