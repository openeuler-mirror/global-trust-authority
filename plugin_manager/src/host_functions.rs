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

/// Trait for host functions
pub trait HostFunctions: Send + Sync {}

/// Function type for validating certificate chains, the parameter is certificate bytes, returns true if the certificate is valid
/// first parameter: certificate type
/// second parameter: user id
/// third parameter: certificate bytes
/// Async function type for validating certificate chains.
/// return value: true if the certificate is valid
pub type ValidateCertChainFn = dyn for<'a> Fn(&'a str, &'a str, &'a [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> + Send + Sync;

/// Function type for getting unmatched measurements, the parameters are measured values, attester_type, returns unmatched measurements
/// first parameter: measured values
/// second parameter: attester_type
/// third parameter: user_id
/// return value: Result with unmatched measurements or error string
pub type GetUnmatchedMeasurementsFn = dyn for<'a> Fn(&'a Vec<String>, &'a str, &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, String>> + Send + 'a>> + Send + Sync;

/// Function type for querying configuration, the parameter is configuration key, returns configuration value
/// first parameter: configuration key
/// return value: configuration json string
pub type QueryConfigurationFn = fn(String) -> Option<String>;

/// Service host functions
pub struct ServiceHostFunctions {
    pub validate_cert_chain: Box<ValidateCertChainFn>,
    pub get_unmatched_measurements: Box<GetUnmatchedMeasurementsFn>,
    pub query_configuration: QueryConfigurationFn,
} 

impl HostFunctions for ServiceHostFunctions {}

impl ServiceHostFunctions {
    /// Create a new instance of ServiceHostFunctions
    pub fn new(validate_cert_chain: Box<ValidateCertChainFn>, get_unmatched_measurements: Box<GetUnmatchedMeasurementsFn>, query_configuration: QueryConfigurationFn) -> Self {
        Self {
            validate_cert_chain,
            get_unmatched_measurements,
            query_configuration,
        }
    }
}

/// Agent host functions
pub struct AgentHostFunctions {
    pub query_configuration: QueryConfigurationFn,
}

impl HostFunctions for AgentHostFunctions {}

impl AgentHostFunctions {
    /// Create a new instance of AgentHostFunctions
    pub fn new(query_configuration: QueryConfigurationFn) -> Self {
        Self {
            query_configuration,
        }
    }
}