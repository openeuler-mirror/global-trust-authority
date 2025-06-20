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

use thiserror::Error;
use validator::ValidationErrors;

mod error_codes {
    pub const PARAM_INVALID: u16 = 10001;
    pub const NOT_SUPPORTED: u16 = 10002;
    pub const IO_FAILED: u16 = 10003;

    pub const OPENBAO_NOT_AVAILABLE: u16 = 20001;
    pub const OPENBAO_COMMAND_EXECUTE_ERROR: u16 = 20002;
    pub const OPENBAO_COMMAND_EXCEPTION: u16 = 20003;
    pub const OPENBAO_JSON_ERROR: u16 = 20004;
    pub const ENV_CONFIG_ERROR: u16 = 20005;
    pub const ASYNC_EXECUTE_ERROR: u16 = 20006;
    pub const ENV_LOAD_ERROR: u16 = 20007;
    pub const CERT_LOAD_ERROR: u16 = 20008;
    pub const FILE_LOAD_ERROR: u16 = 20009;
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Validation failed: {0}")]
    ParamInvalid(String),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("IO error: {0}")]
    IoFailed(#[from] std::io::Error),

    #[error("openbao not available: {0}")]
    OpenbaoNotAvailable(String),

    #[error("openbao command execute error, please check openbao.")]
    OpenbaoCommandExecuteError(String),

    #[error("command execute exception, please check command. {0}")]
    CommandException(String),

    #[error("openbao read private key error")]
    OpenbaoJsonError(String),

    #[error("key manager env read {0} error")]
    EnvConfigError(String),
    
    #[error("async execute error")]
    AsyncExecuteError(String),

    #[error("load .env config error")]
    EnvLoadError(String),

    #[error("load certificate error, msg {0}")]
    CertLoadError(String),

    #[error("load file error, msg {0}")]
    FileLoadError(String),
}

impl AppError {
    pub fn error_code(&self) -> u16 {
        match self {
            Self::ParamInvalid(_) => error_codes::PARAM_INVALID,
            Self::NotSupported(_) => error_codes::NOT_SUPPORTED,
            Self::IoFailed(_) => error_codes::IO_FAILED,
            Self::OpenbaoNotAvailable(_) => error_codes::OPENBAO_NOT_AVAILABLE,
            Self::OpenbaoCommandExecuteError(_) => error_codes::OPENBAO_COMMAND_EXECUTE_ERROR,
            Self::CommandException(_) => error_codes::OPENBAO_COMMAND_EXCEPTION,
            Self::OpenbaoJsonError(_) => error_codes::OPENBAO_JSON_ERROR,
            Self::EnvConfigError(_) => error_codes::ENV_CONFIG_ERROR,
            Self::AsyncExecuteError(_) => error_codes::ASYNC_EXECUTE_ERROR,
            Self::EnvLoadError(_) => error_codes::ENV_LOAD_ERROR,
            Self::CertLoadError(_) => error_codes::CERT_LOAD_ERROR,
            Self::FileLoadError(_) => error_codes::FILE_LOAD_ERROR
        }
    }
}

// 实现从 ValidationErrors 到 AppError 的自动转换
impl From<ValidationErrors> for AppError {
    fn from(errors: ValidationErrors) -> Self {
        // 将验证错误转换为的message
        let error_msg = errors
            .field_errors()
            .values()
            .flat_map(|errs| errs.iter())
            .map(|e| {
                e.message
                    .as_deref()
                    .map(|msg| format!("{}", msg))
                    .unwrap_or_else(|| e.code.to_string())
            })
            .collect::<Vec<_>>()
            .join("; ");
        AppError::ParamInvalid(error_msg)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::errors::error_codes;
    use super::AppError;

    #[test]
    fn test_app_error() {
        let str = String::from("hello world");
        assert_eq!(AppError::ParamInvalid(str.clone()).error_code(), error_codes::PARAM_INVALID);
        assert_eq!(AppError::NotSupported(str.clone()).error_code(), error_codes::NOT_SUPPORTED);
        assert_eq!(AppError::IoFailed(std::io::Error::new(std::io::ErrorKind::Other, str.clone())).error_code(), error_codes::IO_FAILED);
        assert_eq!(AppError::OpenbaoNotAvailable(str.clone()).error_code(), error_codes::OPENBAO_NOT_AVAILABLE);
        assert_eq!(AppError::OpenbaoCommandExecuteError(str.clone()).error_code(), error_codes::OPENBAO_COMMAND_EXECUTE_ERROR);
        assert_eq!(AppError::CommandException(str.clone()).error_code(), error_codes::OPENBAO_COMMAND_EXCEPTION);
        assert_eq!(AppError::OpenbaoJsonError(str.clone()).error_code(), error_codes::OPENBAO_JSON_ERROR);
        assert_eq!(AppError::EnvConfigError(str.clone()).error_code(), error_codes::ENV_CONFIG_ERROR);
        assert_eq!(AppError::AsyncExecuteError(str.clone()).error_code(), error_codes::ASYNC_EXECUTE_ERROR);
        assert_eq!(AppError::EnvLoadError(str.clone()).error_code(), error_codes::ENV_LOAD_ERROR);
        assert_eq!(AppError::CertLoadError(str.clone()).error_code(), error_codes::CERT_LOAD_ERROR);
        assert_eq!(AppError::FileLoadError(str.clone()).error_code(), error_codes::FILE_LOAD_ERROR);
    }
}