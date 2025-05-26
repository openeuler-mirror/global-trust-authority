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
use actix_web::http::header;
use futures::future::{ok, Ready};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

// custom filter
pub struct DefaultFilter;

impl<S, B> Transform<S, ServiceRequest> for DefaultFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = DefaultFilterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(DefaultFilterMiddleware { service })
    }
}

pub struct DefaultFilterMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for DefaultFilterMiddleware<S>
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
        // default filter logic
        log::warn!("=========Default filter: {}", req.path());

        // next middleware
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;

            let  headers = res.headers_mut();

            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".parse().unwrap()
            );

            headers.insert(
                header::X_FRAME_OPTIONS,
                "DENY".parse().unwrap()
            );

            headers.insert(
                header::X_XSS_PROTECTION,
                "0".parse().unwrap()
            );

            headers.insert(
                header::CACHE_CONTROL,
                "no-store, no-cache, must-revalidate".parse().unwrap()
            );

            headers.insert(
                header::STRICT_TRANSPORT_SECURITY,
                "max-age=31536000; includeSubDomains".parse().unwrap()
            );

            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'".parse().unwrap()
            );

            headers.insert(
                header::REFERRER_POLICY,
                "no-referrer-when-downgrade".parse().unwrap()
            );
            
            log::warn!("===========response status: {}.", res.status()
        );
            Ok(res)
        })
    }
}