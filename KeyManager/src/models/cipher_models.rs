use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::utils::response::AppError;

#[derive(Serialize, Deserialize)]
pub struct CreateCipherReq {
    pub key_name: String,
    pub encoding: String,
    pub algorithm: String,
    pub private_key: String,
    pub file_path: String
}

impl CreateCipherReq {
    fn validate_encoding(&self) -> Result<(), AppError> {
        // match self.encoding.as_str() {
        //     "base64" | "hex" | "utf8" => Ok(()),
        //     _ => Err(CommandError::ParamInvalid(format!("无效编码类型: {}", self.encoding))),
        // }
        Ok(())
    }

    fn validate_algorithm(&self) -> Result<(), AppError> {
        // match self.algorithm.as_str() {
        //     "aes-256-gcm" | "chacha20-poly1305" => Ok(()),
        //     _ => Err(CommandError::ParamInvalid(format!("无效算法: {}", self.algorithm))),
        // }
        Ok(())
    }
    // 验证参数private_key和file_path互斥性
    fn validate_private_key_and_file_path_exclusive(&self) -> Result<(), AppError> {
        let has_private = !self.private_key.trim().is_empty();
        let has_file = !self.file_path.trim().is_empty();

        match (has_private, has_file) {
            (true, true) => Err(AppError::ParamInvalid(
                "private_key 和 file_path 不能同时有值".into()
            )),
            (false, false) => Err(AppError::ParamInvalid(
                "必须提供 private_key 或 file_path 其中一个".into()
            )),
            _ => Ok(())
        }
    }

    fn validate_file_path(&self) -> Result<(), AppError> {
        if !self.file_path.is_empty() {
            let path = Path::new(self.file_path.trim());

            // 绝对路径检查
            if !path.is_absolute() {
                return Err(AppError::ParamInvalid(
                    format!("文件路径必须为绝对路径: {}", self.file_path)
                ));
            }

            // 路径规范检查（禁止相对路径组件）
            if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(AppError::ParamInvalid(
                    format!("路径包含非法相对组件: {}", self.file_path)
                ));
            }
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<(), AppError> {
        self.validate_algorithm()?;
        self.validate_encoding()?;
        self.validate_private_key_and_file_path_exclusive()?;
        self.validate_file_path()?;
        Ok(())
    }

}