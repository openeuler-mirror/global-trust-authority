pub mod attestation_strategy;
pub mod strategy_impl;

pub use attestation_strategy::{AttestationStrategy, AttestFuture};
pub use strategy_impl::standard::StandardAttestationStrategy;