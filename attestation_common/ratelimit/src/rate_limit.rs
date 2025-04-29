use std::sync::Arc;
use actix_governor::{Governor, GovernorConfigBuilder, PeerIpKeyExtractor};
use std::env;
use actix_governor::governor::middleware::NoOpMiddleware;

const REQUESTS_PER_SECOND_DEFAULT: u64 = 10;
const BURST_SIZE_DEFAULT: u32 = 5;

fn create_governor(requests_per_second_key: &str, burst_size_key: &str) -> Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>> {
    let requests_per_second = env::var(requests_per_second_key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(REQUESTS_PER_SECOND_DEFAULT);
    let burst_size = env::var(burst_size_key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(BURST_SIZE_DEFAULT);
    Arc::new(Governor::new(&GovernorConfigBuilder::default()
        .requests_per_second(requests_per_second)
        .burst_size(burst_size)
        .finish()
        .unwrap()))
}

pub fn create_management_governor() -> Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>> {
    create_governor("REQUESTS_PER_SECOND", "BURST_SIZE")
}

pub fn create_challenge_governor() -> Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>> {
    create_governor("CHALLENGE_REQUESTS_PER_SECOND", "CHALLENGE_BURST_SIZE")
}