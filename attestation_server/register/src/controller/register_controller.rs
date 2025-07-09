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
use actix_web::{HttpRequest, HttpResponse};
use common_log::debug;
use crate::{apikey::register::{ApiKeyInfo}, service::register_service::register::{register_apikey, update_apikey}, APIKEY, UID};

#[derive(serde::Serialize)]
struct RegisterResponse {
    uid: String,
    apikey: String,
}

pub async fn register(req: HttpRequest) -> HttpResponse {
    let uid = req.headers().get(UID).and_then(|f|f.to_str().ok()).unwrap_or("");
    let apikey = req.headers().get(APIKEY).and_then(|f|f.to_str().ok()).unwrap_or("");
    if uid.is_empty() && apikey.is_empty() {
        // 获取新的uid
        let apikey_info = match register_apikey().await {
            Ok(key) => key,
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({"message":  e.message()}));
            }
        };
        let response = RegisterResponse {
            uid: apikey_info.uid,
            apikey: apikey_info.apikey,
        };
        return HttpResponse::Ok().json(response)
    } else if !uid.is_empty() && !apikey.is_empty() {
        let mut apikey_info = ApiKeyInfo {
            uid: uid.to_string(),
            apikey: apikey.to_string(),
            hashed_key: Vec::new(),
            salt: Vec::new(),
        };
        match update_apikey(&mut apikey_info).await {
            Ok(_) => debug!("update apikey success {:?}", &apikey_info.uid),
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({"message":  e.message()}));
            }
        }
        let response = RegisterResponse {
            uid: apikey_info.uid,
            apikey: apikey_info.apikey,
        };
        return HttpResponse::Ok().json(response)
    } else {
        return HttpResponse::BadRequest().body("uid or apikey is empty");
    }
}