use serde::{Deserialize, Serialize};
use std::path::Path;
use validator::{Validate, ValidationError};

#[derive(Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_private_key_and_file_path_exclusive"))]
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
        message = "The algorithm must be rsa 3072 pss/sm2/ec"
    ))]
    pub algorithm: String,
    #[validate(length(
        max = 2097152,
        message = "The length of the private_key should be less than 2MB "
    ))]
    pub private_key: String,
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
        "rsa 3072 pss" | "sm2" | "ec" => Ok(()),
        _ => Err(ValidationError::new("invalid algorithm")),
    }
}

// 结构体级别校验：private_key 和 file_path 互斥
fn validate_private_key_and_file_path_exclusive(
    req: &CreateCipherReq,
) -> Result<(), ValidationError> {
    let has_private = !req.private_key.trim().is_empty();
    let has_file = !req.file_path.trim().is_empty();

    match (has_private, has_file) {
        (true, true) => Err(ValidationError::new("validate exclusive")
            .with_message("Private_key and file_path cannot have both values".into())),
        (false, false) => Err(ValidationError::new("validate exclusive")
            .with_message("Either private_key or file_path must be provided".into())),
        _ => Ok(()),
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
