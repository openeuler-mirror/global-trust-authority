//! Policy Engine for Remote Attestation
//! 
//! This crate provides functionality to evaluate Rego policies for restful attestation.
//! It supports policy evaluation with comprehensive error handling and size limit validation.
//! 
//! # Features
//! 
//! - Comprehensive error handling for policy compilation and evaluation
//! - Size limit validation for evaluation results 
//! 

mod error;
mod engine;

pub use error::PolicyEvaluationError;
pub use engine::evaluate_policy;
