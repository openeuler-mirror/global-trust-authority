//! Error types for policy evaluation
//! 
//! This module provides error types for handling various failure cases that can occur
//! during policy compilation and evaluation.

use thiserror::Error;

/// Errors that can occur during policy evaluation
///
/// This enum represents the different types of errors that can occur when compiling
/// and evaluating Rego policies. It includes:
///
/// - Compilation errors when the policy syntax is invalid
/// - Evaluation errors when the policy execution fails
/// - Size limit errors when the result exceeds the maximum allowed size
///
#[derive(Debug, Error)]
pub enum PolicyEvaluationError {
    /// Error that occurs when a policy fails to compile due to syntax errors
    #[error("Failed to compile policy: {0}")]
    CompileError(String),

    /// Error that occurs during policy evaluation, such as invalid input or runtime errors
    #[error("Failed to evaluate policy: {0}")]
    EvaluationError(String),

    /// Error that occurs when the policy evaluation result exceeds the size limit
    #[error("Output size limit exceeded: Result size {0} bytes exceeds limit of {1} bytes")]
    OutputSizeLimitError(usize, usize),
}
