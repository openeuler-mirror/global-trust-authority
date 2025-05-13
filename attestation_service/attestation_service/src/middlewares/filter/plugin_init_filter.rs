use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::InternalError;
use actix_web::HttpResponse;
use futures::future::{ok, Ready};
use log::error;
use plugin_manager::{PluginManager, PluginManagerInstance, ServiceHostFunctions, ServicePlugin};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};


/// Check if the plugin manager is initialized
fn check_plugin_initialized() -> bool {
    let manager = PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance();
    manager.is_initialized()
}

// PluginInitFilter
pub struct PluginInitFilter;

impl<S, B> Transform<S, ServiceRequest> for PluginInitFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = PluginInitFilterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PluginInitFilterMiddleware { service })
    }
}

pub struct PluginInitFilterMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for PluginInitFilterMiddleware<S>
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
        // Check if plugin is initialized
        if !check_plugin_initialized() {
            let err = "Plugin is not initialized";
            error!("{}", err);
            return Box::pin(async move {
                Err(InternalError::from_response(
                    "plugin not initialized",
                    HttpResponse::ServiceUnavailable().body("plugin not initialized"),
                )
                .into())
            });
        }

        // If plugin is initialized, continue with the request
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
