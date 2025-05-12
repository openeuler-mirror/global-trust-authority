use actix_web::web;
use ratelimit::Governor;

pub struct RemoteRouteConfigurator;

impl RemoteRouteConfigurator {
    pub fn new() -> Self {
        Self
    }
}

impl super::register::RouteConfigurator for RemoteRouteConfigurator {
    fn register_routes(&self, cfg: &mut web::ServiceConfig, management_governor: Governor) {
    }
}