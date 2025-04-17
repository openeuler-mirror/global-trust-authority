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
