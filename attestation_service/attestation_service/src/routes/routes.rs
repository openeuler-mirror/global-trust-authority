use std::sync::Arc;
use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{Governor, PeerIpKeyExtractor};
use crate::controllers::{token_controller, test_controller, attestation_controller};
use crate::middlewares::filter::key_init_filter::KeyInitFilter;
use crate::middlewares::filter::plugin_init_filter::PluginInitFilter;
use actix_web::web;
use actix_web::web::ServiceConfig;
use resource_provider::routes::register::get_route_configurator;
use resource_provider::routes::register::RouteConfigurator;

/// configure routes
pub fn configure_user_routes(cfg: &mut web::ServiceConfig, challenge_governor: Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>>,
                             management_governor: Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>>) {
    cfg.service(
        web::scope("/nonce")
            .wrap(challenge_governor.clone())
            .route("/getnonce", web::get().to(test_controller::get_nonce))
    );
    
    cfg.service(
        web::scope("/user")
            .wrap(management_governor.clone())
            .route("/all", web::get().to(test_controller::get_all_users))
    );
    cfg.service(
        web::scope("/token")
            .wrap(management_governor.clone())
            .wrap(KeyInitFilter)
            .route("/verify", web::post().to(token_controller::verify_token)),
    );
    cfg.service(
        web::scope("/challenge")
            .wrap(challenge_governor.clone())
            .wrap(PluginInitFilter)
            .route("", web::post().to(attestation_controller::get_nonce)),
    );
    cfg.service(
        web::scope("/attest")
            .wrap(challenge_governor.clone())
            .wrap(PluginInitFilter)
            .route("", web::post().to(attestation_controller::attest)),
    );
    register_config_manager_routes(cfg, management_governor);
}

fn register_config_manager_routes(cfg: &mut ServiceConfig, management_governor: Arc<Governor<PeerIpKeyExtractor, NoOpMiddleware>>) {
    let route_configurator = get_route_configurator();
    route_configurator.register_routes(cfg, management_governor);
}
