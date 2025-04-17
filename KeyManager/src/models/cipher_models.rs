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

    #[validate(custom(function = "validate_encoding", message = "The encoding must be PEM"))]
    pub encoding: String,

    #[validate(custom(
        function = "validate_algorithm",
        message = "The algorithm must be RSA3072/SM2/EC"
    ))]
    pub algorithm: String,

    pub private_key: String,

    pub key_file: String,
}

fn validate_key_name(key_name: &str) -> Result<(), ValidationError> {
    match key_name.to_string().as_str() {
        "FSK" | "NSK" | "TSK" => Ok(()),
        _ => Err(ValidationError::new("invalid key name")),
    }
}

fn validate_encoding(encoding: &str) -> Result<(), ValidationError> {
    match encoding.to_string().as_str() {
        "PEM" => Ok(()),
        _ => Err(ValidationError::new("invalid encoding")),
    }
}

fn validate_algorithm(algorithm: &str) -> Result<(), ValidationError> {
    match algorithm.to_string().as_str() {
        "RSA3072" | "SM2" | "EC" => Ok(()),
        _ => Err(ValidationError::new("invalid algorithm")),
    }
}

// 结构体级校验：根据 encoding/algorithm 校验密钥格式
fn validate_private_key_format(req: &PutCipherReq) -> Result<(), ValidationError> {
    if req.encoding != "PEM" {
        return Ok(());
    }
    let pem_data = if !req.private_key.is_empty() {
        req.private_key.as_bytes()
    } else {
        &fs::read(&req.key_file).map_err(|e| {
            ValidationError::new("FileReadError")
                .with_message(format!("Failed to read key file: {}", e).into())
        })?
    };
    let result = match req.algorithm.as_str() {
        "RSA3072" => validate_rsa3072_key(pem_data),
        "SM2" => validate_sm2_key(pem_data),
        "EC" => validate_ec_key(pem_data),
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

// RSA3072 校验
fn validate_rsa3072_key(pem: &[u8]) -> Result<(), ErrorStack> {
    let pkey = PKey::private_key_from_pem(pem)?;
    let rsa = pkey.rsa()?;
    if rsa.size() * 8 == 3072 {
        Ok(())
    } else {
        log::error!("validate_rsa3072_key failed");
        Err(ErrorStack::get().into())
    }
}

// SM2 校验
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

// EC 校验
fn validate_ec_key(pem: &[u8]) -> Result<(), ErrorStack> {
    let pkey = PKey::private_key_from_pem(pem)?;
    let _ec_key = pkey.ec_key()?;
    Ok(())
}
