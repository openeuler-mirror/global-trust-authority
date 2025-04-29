//! Core policy evaluation engine
//! 
//! This module provides the core functionality for evaluating Rego policies against input data.
//! It handles policy compilation, evaluation, and result size validation.
//! 
//! The main functionality is exposed through the [`evaluate_policy`] function.

use serde_json::{self, Value};
use log::error;
use regorus::Engine;
use crate::error::PolicyEvaluationError;

/// Maximum size limit for policy evaluation result (500KB)
pub(crate) const MAX_RESULT_SIZE: usize = 500 * 1024;

/// Evaluates a Rego policy against the provided input data
///
/// This function takes a JSON input and a Rego policy string, compiles the policy,
/// evaluates it against the input, and returns the result. The function is thread-safe
/// and can be called concurrently from multiple threads.
///
/// # Arguments
///
/// * `input` - The input data to evaluate against, as a JSON Value
/// * `policy` - The Rego policy string to evaluate
///
/// # Returns
///
/// * `Ok(Value)` - The policy evaluation result as a JSON Value
/// * `Err(PolicyEvaluationError)` - An error if policy compilation, evaluation, or size validation fails
///
/// # Errors
///
/// This function will return an error if:
///
/// * The policy fails to compile due to syntax errors (`CompileError`)
/// * The policy evaluation fails due to runtime errors (`EvaluationError`)
/// * The evaluation result exceeds the 500KB size limit (`OutputSizeLimitError`)
///
pub fn evaluate_policy(input: &Value, policy: &str) -> Result<Value, PolicyEvaluationError> {
    let mut engine = Engine::new();
    
    // Add policy
    match engine.add_policy(String::from("verification"), policy.to_string()) {
        Ok(_) => (),
        Err(e) => {
            let err_str = e.to_string();
            error!("Policy compilation error: {}", err_str);
            return Err(PolicyEvaluationError::CompileError(err_str));
        }
    }
    
    // Set input
    let input_str = input.to_string();
    if let Err(e) = engine.set_input_json(&input_str) {
        return Err(PolicyEvaluationError::EvaluationError(format!("Failed to set input: {}", e)));
    }
    
    // Evaluate policy and get result
    let results = match engine.eval_query("data.verification.result".to_string(), false) {
        Ok(results) => results,
        Err(e) => return Err(PolicyEvaluationError::EvaluationError(format!("Failed to evaluate query: {}", e))),
    };
    
    // Extract result
    if results.result.is_empty() {
        return Err(PolicyEvaluationError::EvaluationError("Policy evaluation returned no results".to_string()));
    }
    
    // Convert result to JSON
    if let Some(result) = results.result.first() {
        if let Some(expr) = result.expressions.first() {
            let json_str = match expr.value.to_json_str() {
                Ok(str) => str,
                Err(e) => return Err(PolicyEvaluationError::EvaluationError(format!("Failed to convert result to JSON string: {}", e))),
            };
            
            // Check size limit
            if json_str.len() > MAX_RESULT_SIZE {
                return Err(PolicyEvaluationError::OutputSizeLimitError(json_str.len(), MAX_RESULT_SIZE));
            }
            
            let result_json = match serde_json::from_str(&json_str) {
                Ok(json) => json,
                Err(e) => return Err(PolicyEvaluationError::EvaluationError(format!("Failed to parse JSON string: {}", e))),
            };
            
            return Ok(result_json);
        }
    }
    
    Err(PolicyEvaluationError::EvaluationError("No result returned from policy evaluation".to_string()))
}
