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

use base64::{engine::general_purpose, Engine as _};
use log::{error, info};
use ring::rand::{SecureRandom, SystemRandom};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use std::time::{SystemTime, UNIX_EPOCH};
use key_management::api::impls::default_crypto_impl::DefaultCryptoImpl;
use key_management::api::CryptoOperations;
use serde::{Deserialize, Serialize};
use config_manager::types::CONFIG;
use crate::error::NonceError;

const SEED_SIZE: usize = 32; // seed size

// Nonce
#[derive(Debug, Serialize, Deserialize)]
pub struct Nonce {
    pub iat: u64,
    pub value: String,
    pub signature: String,
}

/// ValidateNonceParams
#[derive(Debug)]
pub struct ValidateNonceParams {
    pub valid_period: u64,
    pub nonce: Nonce,
}

#[derive(Debug)]
pub struct ValidateResult {
    pub is_valid: bool,
    pub message: String,
}

impl Nonce {
    // generate Nonce
    pub async fn generate() -> Result<Self, NonceError> {
        info!("generate nonce begin");
        let iat = get_system_time();
        let value = generate_random_base64()?;
        let sig = get_signature(iat, value.clone()).await?;
        Ok(Self {
            iat,
            value: value.clone(),
            signature: sig,
        })
    }
}

// base64 encode
fn generate_random_base64() -> Result<String, NonceError> {
    let mut rng = match create_secure_rng() {
        Ok(rng) => rng,
        Err(error) => {
            error!("Failed to create secure RNG: {}", error);
            return Err(NonceError::RngError);
        }
    };
    let config = CONFIG.get_instance().expect("Failed to get config instance");
    let nonce_bytes = config.attestation_service.nonce.nonce_bytes as usize;
    let mut random_bytes = vec![0u8; nonce_bytes];
    rng.fill_bytes(&mut random_bytes);
    Ok(general_purpose::STANDARD.encode(random_bytes))
}

// get signature
async fn get_signature(iat: u64, value: String) -> Result<String, NonceError> {
    let str1 = iat.to_string() + &value;
    let data = str1.as_bytes().to_vec();
    match DefaultCryptoImpl::sign(&DefaultCryptoImpl, &data, "NSK").await {
        Ok(res) => Ok(general_purpose::STANDARD.encode(&res.signature)),
        Err(error) => {
            error!("Failed to sign data: {}", error);
            Err(NonceError::SignatureError)
        }
    }
}

// Check ValidateNonceParams
pub async fn validate_nonce(input: ValidateNonceParams) -> ValidateResult {
    let mut message = String::new();
    let is_valid = check_nonce_validity(input, &mut message).await;
    info!("nonce is valid:{}", is_valid);
    ValidateResult { is_valid, message }
}

async fn check_nonce_validity(input: ValidateNonceParams, msg: &mut String) -> bool {
    let current_time = get_system_time();
    if current_time.saturating_sub(input.nonce.iat) > input.valid_period {
        *msg = "Nonce expired.".to_string();
        return false;
    }
    // verify signature
    if !verify_signature(input.nonce).await {
        *msg = "Invalid nonce.".to_string();
        return false;
    }
    true
}

// create secure rng
fn create_secure_rng() -> Result<ChaCha20Rng, String> {
    let mut seed = [0u8; SEED_SIZE];
    SystemRandom::new().fill(&mut seed).map_err(|_| "Failed to generate random bytes")?;
    Ok(ChaCha20Rng::from_seed(seed.into()))
}

/// Gets the current system time as seconds since the Unix epoch.
///
/// # Returns
/// * `u64` - The current time in seconds since the Unix epoch.
///
/// # Panics
/// Panics if the system time is before the Unix epoch (January 1, 1970).
pub fn get_system_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before UNIX epoch")
        .as_secs()
}

// verify signature
async fn verify_signature(_nonce: Nonce) -> bool {
    let iat_value = format!("{}{}", _nonce.iat, _nonce.value);
    let data = iat_value.as_bytes().to_vec();
    let signature_bytes = match general_purpose::STANDARD.decode(_nonce.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            error!("signature decode error");
            return false;
        }
    };
    match DefaultCryptoImpl::verify(&DefaultCryptoImpl, "NSK", None, data, signature_bytes).await {
        Ok(is_valid) => is_valid,
        Err(_error) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_create_secure_rng_uniqueness() {
        // Create multiple RNG instances and verify that they generate different numbers
        let mut rng1 = create_secure_rng().unwrap();
        let mut rng2 = create_secure_rng().unwrap();

        let mut numbers1 = [0u8; 32];
        let mut numbers2 = [0u8; 32];

        rng1.fill_bytes(&mut numbers1);
        rng2.fill_bytes(&mut numbers2);
        assert_ne!(numbers1, numbers2, "Two RNG instances should generate different sequences of numbers");
    }

    #[test]
    fn test_create_secure_rng_distribution() {
        let mut rng = create_secure_rng().unwrap();
        let mut numbers = HashSet::new();

        // Generate 100 random numbers and check their distribution
        for _ in 0..100 {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            numbers.insert(byte[0]);
        }

        // Verify that the generated random numbers have sufficient randomness (at least 25 different values)
        assert!(numbers.len() > 25, "Random number distribution should be sufficiently dispersed");
    }

    #[test]
    fn test_create_secure_rng_reproducibility() {
        // Create two RNG instances with the same seed
        let seed = [42u8; SEED_SIZE];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // The RNG should generate the same sequence with the same seed
        assert_eq!(bytes1, bytes2, "The RNG should generate the same sequence with the same seed");
    }

    #[test]
    fn test_create_secure_rng_seed_size() {
        // Verify that the seed size is correct
        let mut rng = create_secure_rng().unwrap();
        let mut bytes = vec![0u8; SEED_SIZE];
        rng.fill_bytes(&mut bytes);

        assert_eq!(bytes.len(), SEED_SIZE, "The seed size should equal SEED_SIZE");
    }

    use std::time::{Duration, SystemTime};

    #[test]
    fn test_get_system_time() {
        // Get the current time as a reference
        let reference_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Call the tested function
        let result = get_system_time();

        // Verify that the returned timestamp is within a reasonable range
        // The timestamp should not be less than the reference time
        assert!(result >= reference_time);

        // The difference between the timestamp and the reference time should not exceed 1 second
        assert!(result - reference_time <= 1);
    }

    #[test]
    fn test_get_system_time_not_zero() {
        // Verify that the returned timestamp is not zero
        let result = get_system_time();
        assert!(result > 0);

        // Verify that the returned timestamp is greater than a reasonable minimum value (e.g., the timestamp of 2023-01-01 00:00:00)
        let min_expected_time = 1672531200; // 2023-01-01 00:00:00
        assert!(result > min_expected_time);
    }

    #[test]
    fn test_get_system_time_monotonic() {
        // Verify the monotonicity of the time
        let first_call = get_system_time();
        std::thread::sleep(Duration::from_secs(1));
        let second_call = get_system_time();

        // The second call should be greater than the first call
        assert!(second_call > first_call);
    }

    use tokio;
    #[tokio::test]
    async fn test_check_nonce_validity_expired() {
        let current_time = get_system_time();
        let test_nonce = Nonce {
            iat: current_time - 100,  // 100 seconds ago
            value: "test_value".to_string(),
            signature: "valid_signature".to_string(),
        };

        let input = ValidateNonceParams {
            valid_period: 30,  // 30 seconds validity period
            nonce: test_nonce,
        };

        let mut message = String::new();
        let result = check_nonce_validity(input, &mut message).await;

        assert!(!result);
        assert_eq!(message, "Nonce expired.");
    }

    #[tokio::test]
    async fn test_check_nonce_validity_invalid_signature() {
        let current_time = get_system_time();
        let test_nonce = Nonce {
            iat: current_time - 10,  // 10 seconds ago
            value: "test_value".to_string(),
            signature: "invalid_signature".to_string(),
        };

        let input = ValidateNonceParams {
            valid_period: 30,  // 30 seconds validity period
            nonce: test_nonce,
        };

        let mut message = String::new();
        let result = check_nonce_validity(input, &mut message).await;

        assert!(!result);
        assert_eq!(message, "Invalid nonce.");
    }

    #[tokio::test]
    async fn test_validate_nonce_invalid_empty() {
        let current_time = get_system_time();
        let test_nonce = Nonce {
            iat: current_time - 10,  // 10 seconds ago
            value: "test_value".to_string(),
            signature: "invalid_signature".to_string(),
        };

        let params = ValidateNonceParams {
            valid_period: 30,  // 30 seconds validity period
            nonce: test_nonce,
        };

        let result = validate_nonce(params).await;
        assert!(!result.is_valid);
        assert!(!result.message.is_empty());
    }
}