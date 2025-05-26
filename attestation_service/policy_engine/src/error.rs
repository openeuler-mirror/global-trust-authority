/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

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
