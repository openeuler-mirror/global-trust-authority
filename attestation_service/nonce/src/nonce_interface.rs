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
    let config = CONFIG.get_instance().unwrap();
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

// get system time
pub fn get_system_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// verify signature
async fn verify_signature(_nonce: Nonce) -> bool {
    let iat_value = _nonce.iat.to_string() + &_nonce.value;
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
