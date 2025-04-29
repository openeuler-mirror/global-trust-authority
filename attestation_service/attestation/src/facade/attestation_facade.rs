use actix_web::{web, HttpRequest};

use crate::entities::attest_request::AttestRequest;
use crate::strategy::attestation_strategy::AttestFuture;
use crate::{
    factory::attestation_factory::{AttestationFactory, AttestationType},
    strategy::attestation_strategy::AttestationStrategy,
};

pub struct AttestationFacade {
    strategy: Box<dyn AttestationStrategy>,
}

impl AttestationFacade {
    pub fn new(attestation_type: AttestationType) -> Self {
        Self { strategy: AttestationFactory::create_strategy(attestation_type) }
    }

    pub fn process_attestation<'a>(
        &'a self,
        request: &'a web::Json<AttestRequest>,
        http_req: &'a HttpRequest,
    ) -> AttestFuture<'a> {
        self.strategy.attest(request, http_req)
    }
}
