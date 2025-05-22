use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::ErrorTooManyRequests;
use actix_web::Error;
use governor::clock::DefaultClock;
use governor::state::InMemoryState;
use governor::state::NotKeyed;
use governor::{Quota, RateLimiter};
use std::env;
use std::sync::Arc;
// Add this import

const REQUESTS_PER_SECOND_DEFAULT: u32 = 10;
const BURST_SIZE_DEFAULT: u32 = 5;

#[derive(Clone)]
pub struct Governor {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

// Update GovernorMiddleware to match
pub struct GovernorMiddleware<S> {
    service: S,
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl<S, B> Service<ServiceRequest> for GovernorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + 'static>>;

    fn poll_ready(&self, context: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(context)
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let fut = self.service.call(request);
        let limiter = self.limiter.clone();

        Box::pin(async move {
            match limiter.check() {
                Ok(_) => fut.await,
                Err(_) => Err(ErrorTooManyRequests("Too many requests")),
            }
        })
    }
}

impl<S, B> Transform<S, ServiceRequest> for Governor
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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

impl Governor {
    pub fn new(quota: Quota) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::direct(quota)),
        }
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