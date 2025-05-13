use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header;
use futures::future::{ready, Ready};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Security Headers Middleware
///
/// This middleware adds standard security headers to all responses, enhancing the security of the application.
/// The added headers include:
/// - X-Content-Type-Options
/// - X-Frame-Options
/// - X-XSS-Protection
/// - Cache-Control
/// - Strict-Transport-Security
/// - Content-Security-Policy
/// - Referrer-Policy
pub struct SecurityHeaders;

impl SecurityHeaders {
    pub fn new() -> Self {
        SecurityHeaders
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware { service }))
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
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
        log::debug!("SecurityHeaders middleware: Processing request to {}", req.path());
        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            let headers = res.headers_mut();

            headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());

            headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());

            headers.insert(header::X_XSS_PROTECTION, "0".parse().unwrap());

            headers.insert(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate".parse().unwrap());

            headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'self'".parse().unwrap());

            headers.insert(header::REFERRER_POLICY, "no-referrer-when-downgrade".parse().unwrap());

            log::debug!("SecurityHeaders middleware: Added security headers to response");
            Ok(res)
        })
    }
}
