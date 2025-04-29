use std::{future::Future, pin::Pin};

use actix_web::{web, HttpResponse, HttpRequest};

use crate::{entities::attest_request::AttestRequest, error::attestation_error::AttestationError};

type AttestResult = Result<HttpResponse, AttestationError>;
pub type AttestFuture<'a> = Pin<Box<dyn Future<Output = AttestResult> + Send + 'a>>;

pub trait AttestationStrategy {
    fn attest<'a>(
        &'a self,
        request: &'a web::Json<AttestRequest>,
        http_req: &'a HttpRequest
    ) -> AttestFuture<'a>;
}