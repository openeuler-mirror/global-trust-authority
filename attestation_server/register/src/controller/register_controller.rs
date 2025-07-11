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
use crate::{
    apikey::register::ApiKeyInfo,
    service::register_service::register::{register_apikey, update_apikey},
    APIKEY, UID,
};
use actix_web::{HttpRequest, HttpResponse};
use common_log::debug;

#[derive(serde::Serialize)]
struct RegisterResponse {
    #[serde(rename = "User-Id")]
    uid: String,
    #[serde(rename = "API-Key")]
    apikey: String,
}

pub async fn register(req: HttpRequest) -> HttpResponse {
    let uid = match req.headers().get(UID) {
        None => "", // UID 头不存在，视为正常情况，返回空字符串
        Some(header_value) => match header_value.to_str() {
            Ok(uid_str) => uid_str, // 转换成功，返回 UID 字符串
            Err(_) => {
                // 转换出错，拦截请求
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"message":  "UID header contains invalid UTF-8"}));
            },
        },
    };
    let apikey = match req.headers().get(APIKEY) {
        None => "", 
        Some(header_value) => match header_value.to_str() {
            Ok(apikey_str) => apikey_str, 
            Err(_) => {
                // 转换出错，拦截请求
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"message":  "apikey header contains invalid UTF-8"}));
            },
        },
    };
    if uid.is_empty() && apikey.is_empty() {
        // 获取新的uid
        let apikey_info = match register_apikey().await {
            Ok(key) => key,
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({"message":  e.message()}));
            },
        };
        let response = RegisterResponse { uid: apikey_info.uid, apikey: apikey_info.apikey };
        return HttpResponse::Ok().json(response);
    } else if !uid.is_empty() && !apikey.is_empty() {
        let mut apikey_info =
            ApiKeyInfo { uid: uid.to_string(), apikey: apikey.to_string(), hashed_key: Vec::new(), salt: Vec::new() };
        match update_apikey(&mut apikey_info).await {
            Ok(_) => debug!("update apikey success {:?}", &apikey_info.uid),
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({"message":  e.message()}));
            },
        }
        let response = RegisterResponse { uid: apikey_info.uid, apikey: apikey_info.apikey };
        return HttpResponse::Ok().json(response);
    } else {
        return HttpResponse::BadRequest().body("uid or apikey is empty");
    }
}