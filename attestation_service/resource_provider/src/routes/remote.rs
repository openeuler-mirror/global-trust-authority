use std::sync::Arc;
use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{Governor, PeerIpKeyExtractor};
use actix_web::web;
use actix_web::web::ServiceConfig;

pub struct RemoteRouteConfigurator;

impl RemoteRouteConfigurator {
    pub fn new() -> Self {
        Self
    }
}

impl super::register::RouteConfigurator for RemoteRouteConfigurator {
    fn register_routes(&self, cfg: &mut web::ServiceConfig, management_governor: Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>>) {
    }
}