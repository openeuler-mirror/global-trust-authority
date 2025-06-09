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

use actix_web::{web, HttpResponse};
use log::{error, info};
use serde::Deserialize;
use serde_json::json;
use token_management::manager::TokenManager;

/// token controller

/// verify token request parameter
#[derive(Deserialize)]
pub struct TokenRequest {
    token: String,
}

/// verify token restful
pub async fn verify_token(token_req: web::Json<TokenRequest>) -> HttpResponse {
    info!("Start verifying token");
    let token = &token_req.token;

    if token.is_empty() {
        error!("Token is empty");
        return HttpResponse::BadRequest().json(json!({"message": "Token is empty".to_string()}));
    }
    match TokenManager::verify_token(token).await {
        Ok(verify_token_response) => HttpResponse::Ok().json(verify_token_response),
        Err(verify_token_error) => {
            HttpResponse::ServiceUnavailable().json(json!({"message": verify_token_error.to_string()}))
        },
    }
}
