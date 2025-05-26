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

use crate::utils::errors::AppError;
use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, Responder, ResponseError};
use log::error;
use serde::Serialize;

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
            message: "success".into(),
            data: Some(data),
        }
    }

    pub fn ok_without_data() -> Self {
        ApiResponse {
            code: StatusCode::OK.as_u16(),
            message: "success".into(),
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
