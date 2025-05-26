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

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Agent service error types with detailed categorization
#[derive(Debug)]
pub enum AgentError {
    /// Generic errors
    GenericError(String),
    /// Server state errors (started/not started etc.)
    ServerStateError(String),
    /// File errors (certificate/key file not found etc.)
    FileError(String),
    /// Lock errors (mutex acquisition failure etc.)
    LockError(String),
    /// Configuration errors (SSL/TLS configuration issues etc.)
    ConfigError(String),
    /// Load plugin errors
    PluginLoadError(String),
    /// Network errors (binding/connection problems)
    NetworkError(String),
    /// Execution errors
    ExecutionError(String),
    /// Validation errors
    ValidationError(String),
    /// I/O operation errors (file read/write, etc.)
    IoError(String),
    /// Server initialization or configuration error
    ServerInitError(String),
    /// Server shutdown or cleanup error
    ServerShutdownError(String),
    /// Server request handling error
    ServerRequestError(String),
    /// Server response processing error
    ServerResponseError(String),
    /// Scheduler initialization error
    SchedulerInitError(String),
    /// Scheduler task execution error
    SchedulerTaskError(String),
    /// Scheduler shutdown or cleanup error
    SchedulerShutdownError(String),
    /// Scheduler timing or triggering error
    SchedulerTimingError(String),
    /// Invalid path
    InvalidPath(String),
    /// File not found
    FileNotFound(String),
    /// Is not a file
    IsNotFile(String),
    /// Cannot read file
    CannotReadFile(String),
    /// SSL error
    SslError(String),
}

impl Display for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            AgentError::ServerStateError(msg) => write!(f, "Server state error: {}", msg),
            AgentError::FileError(msg) => write!(f, "File error: {}", msg),
            AgentError::LockError(msg) => write!(f, "Lock error: {}", msg),
            AgentError::PluginLoadError(msg) => write!(f, "Plugin load error: {}", msg),
            AgentError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            AgentError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            AgentError::GenericError(msg) => write!(f, "Generic error: {}", msg),
            AgentError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            AgentError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AgentError::IoError(msg) => write!(f, "I/O error: {}", msg),
            AgentError::ServerInitError(msg) => write!(f, "Server initialization error: {}", msg),
            AgentError::ServerShutdownError(msg) => write!(f, "Server shutdown error: {}", msg),
            AgentError::ServerRequestError(msg) => write!(f, "Server request error: {}", msg),
            AgentError::ServerResponseError(msg) => write!(f, "Server response error: {}", msg),
            AgentError::SchedulerInitError(msg) => write!(f, "Scheduler initialization error: {}", msg),
            AgentError::SchedulerTaskError(msg) => write!(f, "Scheduler task error: {}", msg),
            AgentError::SchedulerShutdownError(msg) => write!(f, "Scheduler shutdown error: {}", msg),
            AgentError::SchedulerTimingError(msg) => write!(f, "Scheduler timing error: {}", msg),
            AgentError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            AgentError::FileNotFound(msg) => write!(f, "File not found: {}", msg),
            AgentError::IsNotFile(msg) => write!(f, "Is not a file: {}", msg),
            AgentError::CannotReadFile(msg) => write!(f, "Cannot read file: {}", msg),
            AgentError::SslError(msg) => write!(f, "SSL error: {}", msg),
        }
    }
}

impl Error for AgentError {}

// Make error type thread-safe
unsafe impl Send for AgentError {}
unsafe impl Sync for AgentError {}
