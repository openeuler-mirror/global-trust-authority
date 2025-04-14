use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, Responder, ResponseError};
use log::error;
use serde::Serialize;
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

    #[error("openbao command execute error, please check openbao")]
    OpenbaoCommandExecuteError(String),

    #[error("command execute exception, please check command")]
    CommandException(String),

    #[error("openbao read private key error")]
    OpenbaoJsonError(String),

    #[error("key manager env read {0} error")]
    EnvConfigError(String),
}

impl AppError {
    fn error_code(&self) -> u16 {
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

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub code: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: StatusCode::OK.as_u16(),
            message: "操作成功".into(),
            data: Some(data),
        }
    }

    pub fn ok_without_data() -> Self {
        ApiResponse {
            code: StatusCode::OK.as_u16(),
            message: "操作成功".into(),
            data: None,
        }
    }
}

// 实现Actix自动响应转换
impl<T: Serialize> Responder for ApiResponse<T> {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _: &actix_web::HttpRequest) -> HttpResponse {
        HttpResponse::build(StatusCode::OK)
            .insert_header(ContentType::json())
            .json(self)
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ParamInvalid(_) => StatusCode::BAD_REQUEST,
            Self::NotSupported(_) => StatusCode::BAD_REQUEST,
            Self::IoFailed(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        error!("Request error, {:?}", self);

        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .json(ApiResponse::<()> {
                code: self.error_code(),
                message: self.to_string(),
                data: None,
            })
    }
}

// 实现从 ValidationErrors 到 AppError 的自动转换
impl From<ValidationErrors> for AppError {
    fn from(errors: ValidationErrors) -> Self {
        // 将验证错误转换为友好的错误消息
        let error_msg = errors
            .field_errors()
            .iter()
            .map(|(field, errors)| {
                let details = errors
                    .iter()
                    .map(|e| {
                        let code = e.code.to_string();
                        let msg = e
                            .message
                            .as_ref()
                            .map(|s| format!("{}", s))
                            .unwrap_or_default();
                        format!("{}", msg)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{}", details)
            })
            .collect::<Vec<_>>()
            .join("; ");
        AppError::ParamInvalid(error_msg)
    }
}
