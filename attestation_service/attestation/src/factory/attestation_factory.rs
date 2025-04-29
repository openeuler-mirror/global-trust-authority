use crate::strategy::attestation_strategy::AttestationStrategy;
use crate::strategy::strategy_impl::standard::StandardAttestationStrategy;

pub enum AttestationType {
    Standard,
}

pub struct AttestationFactory;

impl AttestationFactory {
    pub fn create_strategy(attestation_type: AttestationType) -> Box<dyn AttestationStrategy> {
        match attestation_type {
            AttestationType::Standard => Box::new(StandardAttestationStrategy::new()),
        }
    }
}