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
use actix_web::Error;
use futures::future::{ready, LocalBoxFuture, Ready};
use log::info;
use std::task::{Context, Poll};

/// Request Logger Middleware
///
/// This middleware logs detailed information for each incoming HTTP request, including:
/// - HTTP method (GET, POST, etc.)
/// - Request path
/// - Protocol (HTTP/HTTPS)
/// - Client IP address (with optional masking for privacy)
///
/// Logs are output at INFO level for monitoring and troubleshooting purposes.
pub struct RequestLogger;

impl RequestLogger {
    pub fn new() -> Self {
        RequestLogger
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLoggerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggerMiddleware { service }))
    }
}

pub struct RequestLoggerMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>> {
        let conn_info = req.connection_info().clone();
        let real_ip = conn_info.realip_remote_addr().unwrap_or("unknown");
        let masked_ip = mask_ip_address(real_ip); // Masking for privacy
        let method = req.method().clone();
        let path = req.path().to_string();
        let protocol = conn_info.scheme().to_string();

        info!("Request: {} {} {} from {}", method, path, protocol, masked_ip);

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Helper function: Mask IP address for privacy
fn mask_ip_address(ip: &str) -> String {
    if ip.contains('.') {
        // IPv4: Replace the last segment with "*"
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            return format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], "*");
        }
    } else if ip.contains(':') {
        // IPv6: Replace the last two segments with "**"
        let parts: Vec<&str> = ip.split(':').collect();
        if !parts.is_empty() {
            let mut masked_parts = parts[..parts.len() - 2].to_vec();
            masked_parts.push("**");
            return masked_parts.join(":");
        }
    }
    ip.to_string() // If parsing fails, return the original value
}
