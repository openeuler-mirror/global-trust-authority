use crate::controllers::{token_controller, test_controller};
use crate::middlewares::filter::key_init_filter::KeyInitFilter;
use actix_web::web;
use actix_web::web::ServiceConfig;
use resource_provider::routes::register::get_route_configurator;
use resource_provider::routes::register::RouteConfigurator;
use ratelimit::Governor;

/// configure routes
pub fn configure_user_routes(cfg: &mut web::ServiceConfig, challenge_governor:Governor, management_governor:Governor) {
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
    register_config_manager_routes(cfg, management_governor);
}

fn register_config_manager_routes(cfg: &mut ServiceConfig, management_governor:Governor) {
    let route_configurator = get_route_configurator();
    route_configurator.register_routes(cfg, management_governor);
}
