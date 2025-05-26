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

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use futures::future::{ok, Ready};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use actix_web::error::InternalError;
use actix_web::HttpResponse;
use log::error;
use key_management::key_manager::key_initialization::{is_initialized};

// KeyInitFilter
pub struct KeyInitFilter;

impl<S, B> Transform<S, ServiceRequest> for KeyInitFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = KeyInitFilterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(KeyInitFilterMiddleware { service })
    }
}

pub struct KeyInitFilterMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for KeyInitFilterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // key init filter logic
        log::warn!("=========Key init filter: {}", req.path());
        if !is_initialized() {
            error!("Attempted to generate token with uninitialized key.");
            return Box::pin(async move {
                Err(InternalError::from_response(
                    "Key not initialized",
                    HttpResponse::ServiceUnavailable().body("Key not initialized"),
                ).into())
            });
        }
        // next middleware
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            log::warn!("===========response status: {}, headers: {:?}",
            res.status(),
            res.headers()
        );
            Ok(res)
        })
    }
}