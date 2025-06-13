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

use actix_web::{http::StatusCode, HttpResponse};
use log::error;
use serde_json::json;

/// Creates a standardized error response for HTTP endpoints
///
/// # Arguments
/// * `error` - Any error type that implements Display trait
/// * `status` - HTTP status code for the response
///
/// # Returns
/// * `HttpResponse` - JSON formatted error response with message
///
/// # Behavior
/// - For `BAD_REQUEST` (400), logs as request validation failure
/// - For other status codes, logs as operation failure
/// - Returns JSON response with error message and appropriate status code
pub fn create_error_response(error: impl std::fmt::Display, status: StatusCode) -> HttpResponse {
    let message = error.to_string();
    if status == StatusCode::BAD_REQUEST {
        error!("Request validation failed: {}", message);
    } else {
        error!("Operation failed: {}", message);
    }
    HttpResponse::build(status).json(json!({ "message": message }))
}
