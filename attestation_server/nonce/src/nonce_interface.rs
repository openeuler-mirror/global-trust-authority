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
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use key_management::api::impls::default_crypto_impl::DefaultCryptoImpl;
use key_management::api::CryptoOperations;
use serde::Serialize;
use config_manager::types::CONFIG;

const SEED_SIZE: usize = 32; // seed size

// Nonce
#[derive(Debug, Serialize)]
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
    pub async fn generate() -> Self {
        info!("generate nonce begin");
        let iat = get_system_time();
        let value = generate_random_base64();
        Self {
            iat,
            value: value.clone(),
            signature:  get_signature(iat, value).await
        }
    }
}

// base64 encode
fn generate_random_base64() -> String {
    let mut rng = create_secure_rng();
    let config = CONFIG.get_instance().expect("Failed to get config instance");
    let nonce_bytes = config.attestation_service.nonce.nonce_bytes;
    let mut random_bytes = vec![0u8; nonce_bytes as usize];
    rng.fill_bytes(&mut random_bytes);
    general_purpose::STANDARD.encode(random_bytes)
}

// get signature
async fn get_signature(iat: u64, value: String) -> String {
    let str1 = iat.to_string() + &value;
    let data = str1.as_bytes().to_vec();
    match DefaultCryptoImpl::sign(&DefaultCryptoImpl, &data, "NSK").await {
        Ok(res) => general_purpose::STANDARD.encode(&res.signature),
        Err(_error) => Err(_error).expect("Failed to generate signature"),
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
    info!("check nonce validity begin.");
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
    info!("check nonce validity end.");
    true
}

// create secure rng
fn create_secure_rng() -> ChaCha20Rng {
    let mut seed = [0u8; SEED_SIZE];
    rand::thread_rng().fill_bytes(&mut seed);
    ChaCha20Rng::from_seed(seed)
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
        // 创建多个RNG实例并验证它们生成的数字是否不同
        let mut rng1 = create_secure_rng();
        let mut rng2 = create_secure_rng();

        let mut numbers1 = [0u8; 32];
        let mut numbers2 = [0u8; 32];

        rng1.fill_bytes(&mut numbers1);
        rng2.fill_bytes(&mut numbers2);
        assert_ne!(numbers1, numbers2, "两个RNG实例生成的数字序列不应相同");
    }

    #[test]
    fn test_create_secure_rng_distribution() {
        let mut rng = create_secure_rng();
        let mut numbers = HashSet::new();

        // 生成100个随机数并检查其分布
        for _ in 0..100 {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            numbers.insert(byte[0]);
        }

        // 验证生成的随机数具有足够的随机性（至少产生了25个不同的值）
        assert!(numbers.len() > 25, "随机数分布应该足够分散");
    }

    #[test]
    fn test_create_secure_rng_reproducibility() {
        // 使用相同的种子创建两个RNG实例
        let seed = [42u8; SEED_SIZE];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // 相同种子的RNG应产生相同的序列
        assert_eq!(bytes1, bytes2, "相同种子的RNG应产生相同的序列");
    }

    #[test]
    fn test_create_secure_rng_seed_size() {
        // 验证种子大小是否正确
        let mut rng = create_secure_rng();
        let mut bytes = vec![0u8; SEED_SIZE];
        rng.fill_bytes(&mut bytes);

        assert_eq!(bytes.len(), SEED_SIZE, "生成的种子大小应该等于SEED_SIZE");
    }

    use std::time::{Duration, SystemTime};

    #[test]
    fn test_get_system_time() {
        // 获取当前时间作为参考
        let reference_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 调用被测试函数
        let result = get_system_time();

        // 验证返回的时间戳在合理范围内
        // 时间戳应该不小于参考时间
        assert!(result >= reference_time);

        // 时间戳与参考时间的差值不应超过1秒
        assert!(result - reference_time <= 1);
    }

    #[test]
    fn test_get_system_time_not_zero() {
        // 验证返回的时间戳不为0
        let result = get_system_time();
        assert!(result > 0);

        // 验证返回的时间戳大于某个合理的最小值（例如：2023年的时间戳）
        let min_expected_time = 1672531200; // 2023-01-01 00:00:00
        assert!(result > min_expected_time);
    }

    #[test]
    fn test_get_system_time_monotonic() {
        // 验证时间的单调性
        let first_call = get_system_time();
        std::thread::sleep(Duration::from_secs(1));
        let second_call = get_system_time();

        // 第二次调用应该大于第一次调用
        assert!(second_call > first_call);
    }

    use tokio;
    #[tokio::test]
    async fn test_check_nonce_validity_expired() {
        let current_time = get_system_time();
        let test_nonce = Nonce {
            iat: current_time - 100,  // 100秒前创建
            value: "test_value".to_string(),
            signature: "valid_signature".to_string(),
        };

        let input = ValidateNonceParams {
            valid_period: 30,  // 30秒有效期
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
            iat: current_time - 10,  // 10秒前创建
            value: "test_value".to_string(),
            signature: "invalid_signature".to_string(),
        };

        let input = ValidateNonceParams {
            valid_period: 30,  // 30秒有效期
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
            iat: current_time - 10,  // 10秒前创建
            value: "test_value".to_string(),
            signature: "invalid_signature".to_string(),
        };

        let params = ValidateNonceParams {
            valid_period: 30,  // 30秒有效期
            nonce: test_nonce,
        };

        let result = validate_nonce(params).await;
        assert!(!result.is_valid);
        assert!(!result.message.is_empty());
    }
}