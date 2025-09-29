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
use actix_web::{dev::{Service, ServiceRequest, ServiceResponse, Transform}, web, Error};
use futures::executor::block_on;
use futures_util::future::{ready, LocalBoxFuture, Ready};
use lazy_static::lazy_static;
use std::{
    task::{Context, Poll},
    vec,
};
use std::sync::Arc;
use sea_orm::DatabaseConnection;
use common_log::{error, info};
use crate::{apikey::register::ApiKeyInfo, service::register_service::register::check_apikey, APIKEY, UID};

pub struct AuthFilter;

impl<S, B> Transform<S, ServiceRequest> for AuthFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthFilterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthFilterMiddleware { service }))
    }
}

pub struct AuthFilterMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthFilterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if !*APIKEY_ENABLE {
            return Box::pin(self.service.call(req));
        }
        let uid = match req.headers().get(UID) {
            None => "",
            Some(header_value) => match header_value.to_str() {
                Ok(uid_str) => uid_str,
                Err(_) => {
                    return Box::pin(async {
                        Err(actix_web::error::ErrorBadRequest("UID header contains invalid UTF-8"))
                    });
                },
            },
        };

        let apikey = match req.headers().get(APIKEY) {
            None => "",
            Some(header_value) => match header_value.to_str() {
                Ok(apikey_str) => apikey_str,
                Err(_) => {
                    return Box::pin(async {
                        Err(actix_web::error::ErrorBadRequest("APIKEY header contains invalid UTF-8"))
                    });
                },
            },
        };
        if apikey.is_empty() && uid.is_empty() && req.path().ends_with("register") {
            return Box::pin(self.service.call(req));
        }
        // validate token url
        if req.path().ends_with("/token/verify") {
            return Box::pin(self.service.call(req));
        }
        let db = match req.app_data::<web::Data<Arc<DatabaseConnection>>>() {
            Some(db) => db,     
            None => {
                return Box::pin(async {
                    error!("db connect load error!");
                    Err(actix_web::error::ErrorInternalServerError("db connect load error!"))
                });
            },
        };
        let auth_result = block_on(check_apikey(&ApiKeyInfo {
            apikey: apikey.to_string(),
            uid: uid.to_string(),
            salt: vec![],
            hashed_key: vec![],
        }, db.clone()));

        match auth_result {
            Ok(true) => Box::pin(self.service.call(req)),
            Ok(false) => Box::pin(async {Err(actix_web::error::ErrorUnauthorized("Invalid API key"))}),
            Err(e) => Box::pin(async move {Err(actix_web::error::ErrorBadRequest(format!("Validation error: {}", e)))}),
        }
    }
}

lazy_static! {
    pub static ref APIKEY_ENABLE: bool = get_api_key_enable();
}

pub fn get_api_key_enable() -> bool {
    match std::env::var("ENABLE_APIKEY") {
        Ok(val) => {
            match val.parse::<bool>() {
                Ok(enable) => {
                    info!("ENABLE_APIKEY set to {}", enable);
                    enable
                },
                Err(_e) => {
                    error!("ENABLE_APIKEY env is not bool, use default value false");
                    false
                }
            }
        },
        Err(e) => {
            error!("Environment variable ENABLE_APIKEY not found: {}, use default value false", e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_enable_apikey_true() {
        unsafe { env::set_var("ENABLE_APIKEY", "true"); }
        assert!(get_api_key_enable());
        unsafe { env::remove_var("ENABLE_APIKEY"); }
    }

    #[test]
    fn test_enable_apikey_false() {
        unsafe { env::set_var("ENABLE_APIKEY", "false"); }
        assert!(!get_api_key_enable());
        unsafe { env::remove_var("ENABLE_APIKEY"); }
    }

    #[test]
    fn test_enable_apikey_invalid_value() {
        // Remove any existing ENABLE_APIKEY to ensure clean state
        unsafe { env::remove_var("ENABLE_APIKEY"); }
        unsafe { env::set_var("ENABLE_APIKEY", "not_a_boolean"); }
        // Call get_api_key_enable() directly instead of using the lazy_static value
        // which was initialized when the module was first loaded
        assert!(!get_api_key_enable());
        unsafe { env::remove_var("ENABLE_APIKEY"); }
    }

    #[test]
    fn test_enable_apikey_case_insensitive() {
        unsafe { env::set_var("ENABLE_APIKEY", "TRUE"); }
        assert!(!get_api_key_enable());
        unsafe { env::remove_var("ENABLE_APIKEY"); }
    }
}
