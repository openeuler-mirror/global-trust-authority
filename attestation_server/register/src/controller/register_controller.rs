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
use std::sync::Arc;
use crate::{
    apikey::register::ApiKeyInfo,
    service::register_service::register::{register_apikey, update_apikey},
    APIKEY, UID,
};
use actix_web::{web, HttpRequest, HttpResponse};
use sea_orm::DatabaseConnection;
use common_log::debug;

#[derive(serde::Serialize,  serde::Deserialize)]
struct RegisterResponse {
    #[serde(rename = "User-Id")]
    uid: String,
    #[serde(rename = "API-Key")]
    apikey: String,
}

pub async fn register(req: HttpRequest, db: web::Data<Arc<DatabaseConnection>>) -> HttpResponse {
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
        let apikey_info = match register_apikey(db).await {
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
        match update_apikey(&mut apikey_info, db).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{web};
    use mockall::predicate::*;
    use std::sync::Arc;
    use actix_web::body::to_bytes;
    use actix_web::http::header::HeaderValue;
    use actix_web::http::StatusCode;
    use actix_web::test::TestRequest;
    use sea_orm::{ConnectionTrait, Database};
    use crate::error::register_error::RegisterError;

    async fn setup_test_db() -> Result<web::Data<Arc<DatabaseConnection>>, RegisterError> {
        let db = Database::connect("sqlite::memory:?mode=memory&cache=shared").await
            .map_err(|e| RegisterError::DatabaseError(e.to_string()))?;
        db.execute(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "
        CREATE TABLE IF NOT EXISTS t_apikey_info (
            uid TEXT NOT NULL,
            hashed_key TEXT NOT NULL,
            salt TEXT NOT NULL
        );
    ".to_string())).await.map_err(|e| RegisterError::DatabaseError(e.to_string()))?;
        db.execute(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "
        CREATE TABLE IF NOT EXISTS dual (dummy INTEGER);
        INSERT OR IGNORE INTO dual VALUES (1);
    ".to_string())).await.map_err(|e| RegisterError::DatabaseError(e.to_string()))?;
        Ok(web::Data::new(Arc::new(db)))
    }

    // 创建带有指定头部的测试请求
    fn test_request(uid: &str, apikey: &str) -> HttpRequest {
        TestRequest::default()
            .insert_header((UID, uid))
            .insert_header((APIKEY, apikey))
            .to_http_request()
    }

    #[tokio::test]
    async fn test_register_new_key() {
        let db =  setup_test_db().await.unwrap();
        let req = TestRequest::default().to_http_request(); // 无头部的请求
        let resp = register(req, db).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body()).await.unwrap();
        let body: RegisterResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!body.uid.is_empty());
        assert!(!body.apikey.is_empty());
    }

    #[tokio::test]
    async fn test_register_update_key() {
        let db =  setup_test_db().await.unwrap();
        let req = TestRequest::default().to_http_request(); 
        let resp = register(req, db.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body()).await.unwrap();
        let body1: RegisterResponse = serde_json::from_slice(&bytes).unwrap();
        let req = test_request(&body1.uid, &body1.apikey);
        let resp = register(req, db).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body()).await.unwrap();
        let body: RegisterResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.uid, body1.uid);
    }

    #[tokio::test]
    async fn test_register_invalid_headers() {
        let db =  setup_test_db().await.unwrap();
        let req = TestRequest::default()
            .insert_header((UID, HeaderValue::from_bytes(b"\xFA\x80").unwrap()))
            .to_http_request();
        let resp = register(req, db.clone()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let req = test_request("only_uid", "");
        let resp = register(req, db).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}