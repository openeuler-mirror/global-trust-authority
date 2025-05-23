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

use actix_web::body::BoxBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpResponse};
use futures::future::{ok, LocalBoxFuture, Ready};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use once_cell::sync::Lazy;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::task::{Context, Poll};

const PER_SECOND_REQUEST: u32 = 2;
const ALLOW_BURST: u32 = 3;

pub static GLOBAL_LIMITER: Lazy<Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>> = Lazy::new(|| {
    let quota = Quota::per_second(NonZeroU32::new(PER_SECOND_REQUEST).unwrap())
        .allow_burst(NonZeroU32::new(ALLOW_BURST).unwrap());
    Arc::new(RateLimiter::keyed(quota))
});

pub struct RateLimit;

impl<S, B> Transform<S, ServiceRequest> for RateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimitMiddleware { service })
    }
}

pub struct RateLimitMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let limiter = req
            .app_data::<Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>>()
            .cloned()
            .unwrap_or_else(|| GLOBAL_LIMITER.clone());
        if limiter.check_key(&"global".to_string()).is_ok() {
            let fut = self.service.call(req);
            Box::pin(async move { fut.await.map(|res| res.map_into_boxed_body()) })
        } else {
            Box::pin(async move {
                let (req, _pl) = req.into_parts();
                let res = HttpResponse::TooManyRequests().body("Too Many Requests").map_into_boxed_body();
                Ok(ServiceResponse::new(req, res))
            })
        }
    }
}
