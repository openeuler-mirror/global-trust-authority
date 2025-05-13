use std::env;
use governor::{Quota, RateLimiter};
use std::sync::Arc;
use std::net::IpAddr;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::ErrorTooManyRequests;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use actix_web::Error;

const REQUESTS_PER_SECOND_DEFAULT: u32 = 10;
const BURST_SIZE_DEFAULT: u32 = 5;

#[derive(Clone)]
pub struct Governor {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

// ... rest of the code ...

impl Governor {
    pub fn new(quota: Quota) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Governor
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = GovernorMiddleware<S>;
    type InitError = ();
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(GovernorMiddleware {
            service,
            limiter: self.limiter.clone(),
        }))
    }
}

pub struct GovernorMiddleware<S> {
    service: S,
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

impl<S, B> Service<ServiceRequest> for GovernorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = req.peer_addr()
            .map(|addr| addr.ip())
            .unwrap_or_else(|| "0.0.0.0".parse().unwrap());

        let fut = self.service.call(req);
        let limiter = self.limiter.clone();

        Box::pin(async move {
            match limiter.check_key(&ip) {
                Ok(_) => fut.await,
                Err(_) => Err(ErrorTooManyRequests("Too many requests")),
            }
        })
    }
}

fn create_governor(requests_per_second_key: &str, burst_size_key: &str) -> Governor {
    let requests_per_second = env::var(requests_per_second_key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(REQUESTS_PER_SECOND_DEFAULT);
    let burst_size = env::var(burst_size_key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(BURST_SIZE_DEFAULT);
    let management_quota = Quota::per_second(std::num::NonZeroU32::new(requests_per_second).unwrap())
        .allow_burst(std::num::NonZeroU32::new(burst_size).unwrap());
    Governor::new(management_quota)
}

pub fn create_management_governor() -> Governor {
    create_governor("REQUESTS_PER_SECOND", "BURST_SIZE")
}

pub fn create_challenge_governor() -> Governor {
    create_governor("CHALLENGE_REQUESTS_PER_SECOND", "CHALLENGE_BURST_SIZE")
}