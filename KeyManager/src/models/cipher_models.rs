use serde::{Deserialize, Serialize};
use std::path::Path;
use validator::{Validate, ValidationError};

#[derive(Serialize, Deserialize, Validate, Debug)]
pub struct CreateCipherReq {
    #[validate(length(
        min = 1,
        max = 32,
        message = "The length of the key name should be between 1 and 32 characters"
    ))]
    pub key_name: String,

    #[validate(custom(function = "validate_encoding", message = "The encoding must be PEM"))]
    pub encoding: String,

    #[validate(custom(
        function = "validate_algorithm",
        message = "The algorithm must be RSA3072/SM2/EC"
    ))]
    pub algorithm: String,

    #[validate(length(
        max = 2097152,
        message = "The length of the private_key should be less than 2MB "
    ))]
    pub private_key: String
    ,
    #[validate(custom(function = "validate_file_path"))]
    pub file_path: String,
}

fn validate_encoding(encoding: &str) -> Result<(), ValidationError> {
    match encoding.to_lowercase().as_str() {
        "pem" => Ok(()),
        _ => Err(ValidationError::new("invalid encoding")),
    }
}

fn validate_algorithm(algorithm: &str) -> Result<(), ValidationError> {
    match algorithm.to_lowercase().as_str() {
        "rsa3072" | "sm2" | "ec" => Ok(()),
        _ => Err(ValidationError::new("invalid algorithm")),
    }
}

fn validate_file_path(file_path: &str) -> Result<(), ValidationError> {
    if file_path.is_empty() {
        return Ok(());
    }
    let path = Path::new(file_path.trim());

    // 绝对路径检查
    if !path.is_absolute() {
        return Err(ValidationError::new("validate file path")
            .with_message("File path must be an absolute path".into()));
    }

    // 路径规范检查（禁止相对路径组件）
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(
            ValidationError::new("validate file path").with_message("Invalid file path".into())
        );
    }

    Ok(())
}
