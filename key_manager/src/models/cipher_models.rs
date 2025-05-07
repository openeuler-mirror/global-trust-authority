use crate::config::config::TOKEN_ARRAY;
use crate::constants::{
    ALGORITHM_EC, ALGORITHM_RSA_3072, ALGORITHM_RSA_4096, ALGORITHM_SM2, ENCODING_PEM,
    RSA_3072_KEY_SIZE, RSA_4096_KEY_SIZE, MAX_PRIVATE_KEY_SIZE,
};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use std::fs;
use validator::{Validate, ValidationError};

#[derive(Serialize, Deserialize, Validate, Debug)]
#[validate(schema(function = "validate_private_key_format"))]
pub struct PutCipherReq {
    #[validate(custom(
        function = "validate_key_name",
        message = "The key name must be  FSK/NSK/TSK"
    ))]
    pub key_name: String,

    #[validate(custom(function = "validate_encoding", message = "The encoding must be pem"))]
    pub encoding: String,

    #[validate(custom(
        function = "validate_algorithm",
        message = "The algorithm must be rsa_3072/rsa_4096/sm2/ec"
    ))]
    pub algorithm: String,

    pub private_key: String,

    pub key_file: String,
}

fn validate_key_name(key_name: &str) -> Result<(), ValidationError> {
    if TOKEN_ARRAY.contains(&key_name) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid key name"))
    }
}

fn validate_encoding(encoding: &str) -> Result<(), ValidationError> {
    match encoding.to_string().as_str() {
        ENCODING_PEM => Ok(()),
        _ => Err(ValidationError::new("invalid encoding")),
    }
}

fn validate_algorithm(algorithm: &str) -> Result<(), ValidationError> {
    match algorithm.to_string().as_str() {
        ALGORITHM_RSA_3072 | ALGORITHM_RSA_4096 | ALGORITHM_SM2 | ALGORITHM_EC => Ok(()),
        _ => Err(ValidationError::new("invalid algorithm")),
    }
}

// 结构体级校验：根据 encoding/algorithm 校验密钥格式
fn validate_private_key_format(req: &PutCipherReq) -> Result<(), ValidationError> {
    if req.encoding != ENCODING_PEM {
        return Ok(());
    }
    let pem_data = if !req.private_key.is_empty() {
        if req.key_file.len() > (MAX_PRIVATE_KEY_SIZE as usize) {
            return Err(ValidationError::new("PrivateKeyTooLarge")
                .with_message(format!("Private Key length exceeds {}MB limit",
                                      MAX_PRIVATE_KEY_SIZE /1024/1024).into()));
        }
        req.private_key.as_bytes()
    } else {
        let file_meta = fs::metadata(&req.key_file)
            .map_err(|e| ValidationError::new("FileReadError")
                .with_message(format!("File metadata read failed: {}", e).into()))?;

        if file_meta.len() > MAX_PRIVATE_KEY_SIZE {
            return Err(ValidationError::new("FileTooLarge")
                .with_message(format!("Key file: {} exceeds {}MB limit",
                                      req.key_file, MAX_PRIVATE_KEY_SIZE /1024/1024).into()));
        }
        &fs::read(&req.key_file).map_err(|e| {
            ValidationError::new("FileReadError")
                .with_message(format!("Failed to read key file: {}", e).into())
        })?
    };
    let result = match req.algorithm.as_str() {
        ALGORITHM_RSA_3072 => validate_rsa(pem_data, RSA_3072_KEY_SIZE),
        ALGORITHM_RSA_4096 => validate_rsa(pem_data, RSA_4096_KEY_SIZE),
        ALGORITHM_SM2 => validate_sm2_key(pem_data),
        ALGORITHM_EC => validate_ec_key(pem_data),
        _ => Err(ErrorStack::get().into()),
    };

    result.map_err(|_| {
        let mut err = ValidationError::new("InvalidKeyFormat");
        err.message = Some(
            format!(
                "Private key does not match {} algorithm format, please check",
                req.algorithm
            )
            .into(),
        );
        err.add_param("algorithm".into(), &req.algorithm);
        err
    })
}

fn validate_rsa(pem_data: &[u8], size: u32) -> Result<(), ErrorStack> {
    let pkey = PKey::private_key_from_pem(pem_data)?;
    let rsa = pkey.rsa()?;
    if rsa.size() * 8 == size {
        Ok(())
    } else {
        log::error!("RSA {} key validation failed: Incorrect key size", size);
        Err(ErrorStack::get().into())
    }
}

// sm2 校验
fn validate_sm2_key(pem: &[u8]) -> Result<(), ErrorStack> {
    let pkey = PKey::private_key_from_pem(pem)?;
    let ec_key = pkey.ec_key()?;
    let group = ec_key.group();
    if group.curve_name() == Some(Nid::SM2) {
        Ok(())
    } else {
        Err(ErrorStack::get().into())
    }
}

// ec 校验
fn validate_ec_key(pem: &[u8]) -> Result<(), ErrorStack> {
    let pkey = PKey::private_key_from_pem(pem)?;
    let _ec_key = pkey.ec_key()?;
    Ok(())
}
