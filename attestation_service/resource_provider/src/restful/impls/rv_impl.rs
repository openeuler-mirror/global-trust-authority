use actix_web::HttpResponse;
use crate::resource_facade::Rv;

pub struct RvImpl;

impl RvImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Rv for RvImpl {
    fn do_something(&self) -> HttpResponse {
        HttpResponse::InternalServerError().body("The independent deployment feature is not supported")
    }
}