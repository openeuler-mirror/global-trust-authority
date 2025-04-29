use std::sync::Arc;
use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{Governor, PeerIpKeyExtractor};
use actix_web::web;
#[cfg(feature = "co-deployment")]
use crate::routes::local::LocalRouteConfigurator;
#[cfg(feature = "independent-deployment")]
use crate::routes::remote::RemoteRouteConfigurator;

pub trait RouteConfigurator {
    fn register_routes(&self, cfg: &mut web::ServiceConfig, management_governor: Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>>);
}

// Select implementation based on features
#[cfg(feature = "co-deployment")]
pub fn get_route_configurator() -> impl RouteConfigurator {
    LocalRouteConfigurator::new()
}

#[cfg(feature = "independent-deployment")]
pub fn get_route_configurator() -> impl RouteConfigurator {
    RemoteRouteConfigurator::new()  // empty implementation
}