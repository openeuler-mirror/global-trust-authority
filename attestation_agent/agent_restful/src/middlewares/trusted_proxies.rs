use crate::rest::ServiceConfig;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::Error;
use futures::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;
use std::task::{Context, Poll};

/// Trusted Proxies Middleware
///
/// This middleware handles trusted proxy configuration by:
/// 1. Adding X-Forwarded-* headers when trusted proxies are configured
/// 2. Adding X-Trusted-Proxy-* headers for each trusted proxy
pub struct TrustedProxies {
    config: Arc<ServiceConfig>,
}

impl TrustedProxies {
    pub fn new(config: &ServiceConfig) -> Self {
        TrustedProxies { config: Arc::new(config.clone()) }
    }
}

impl<S, B> Transform<S, ServiceRequest> for TrustedProxies
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = TrustedProxiesMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(TrustedProxiesMiddleware { service, config: self.config.clone() }))
    }
}

pub struct TrustedProxiesMiddleware<S> {
    service: S,
    config: Arc<ServiceConfig>,
}

impl<S, B> Service<ServiceRequest> for TrustedProxiesMiddleware<S>
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

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = self.config.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            if !config.trusted_proxies.is_empty() {
                let headers = res.headers_mut();

                headers.insert(HeaderName::from_static("x-forwarded-host"), HeaderValue::from_static("true"));
                headers.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("true"));
                headers.insert(HeaderName::from_static("x-forwarded-for"), HeaderValue::from_static("true"));

                for (i, proxy) in config.trusted_proxies.iter().enumerate() {
                    if let Ok(header_name) = HeaderName::try_from(format!("x-trusted-proxy-{}", i + 1)) {
                        if let Ok(header_value) = HeaderValue::try_from(proxy.as_str()) {
                            headers.insert(header_name, header_value);
                        }
                    }
                }
            }

            Ok(res)
        })
    }
}
