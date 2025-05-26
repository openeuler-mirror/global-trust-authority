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

use serde::Deserialize;
use crate::ConfigSingleton;

/// Main configuration structure that matches the server_config.yaml file structure.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Common configuration settings
    pub attestation_common: Option<AttestationCommon>,
    /// Service-specific configuration settings
    pub attestation_service: AttestationService,
}

/// Common configuration settings
#[derive(Debug, Deserialize, Clone)]
pub struct AttestationCommon {
    /// YAML parsing support information
    pub yaml_parse_support: String,
}

/// Nonce configuration settings
#[derive(Debug, Deserialize, Clone)]
pub struct NonceConfig {
    /// Nonce valid period in seconds
    pub nonce_valid_period: u64,
    /// Nonce bytes
    pub nonce_bytes: u64
}

/// Plugin configuration
#[derive(Debug, Deserialize, Clone)]
pub struct Plugin {
    /// Plugin name
    pub name: String,
    /// Plugin path
    pub path: String,
}

/// Export policy file configuration
#[derive(Debug, Deserialize, Clone)]
pub struct ExportPolicyFile {
    /// Policy name
    pub name: String,
    /// Policy path
    pub path: String,
}

/// Policy configuration settings
#[derive(Debug, Deserialize, Clone)]
pub struct Policy {
    /// Export policy file configurations
    pub export_policy_file: Vec<ExportPolicyFile>,
    /// Whether to verify policy signature
    pub is_verify_policy_signature: bool,
    /// Single user policy limit
    pub single_user_policy_limit: u32,
    /// Policy content size limit
    pub policy_content_size_limit: u32,
    /// Query user policy limit
    pub query_user_policy_limit: u32,
}

/// Service-specific configuration settings
#[derive(Debug, Deserialize, Clone)]
pub struct AttestationService {
    /// Attestation verifier configuration
    pub key_management: KeyManagement,
    /// Token management configuration
    pub token_management: TokenManagement,
    /// Policy configuration
    pub policy: Policy,
    /// Cert configuration
    pub cert: Cert,
    /// Nonce configuration
    pub nonce: NonceConfig,
    /// Plugin configurations
    pub plugins: Vec<Plugin>,
}

/// Attestation verifier configuration
#[derive(Debug, Deserialize, Clone)]
pub struct KeyManagement {
    /// URL for retrieving signing keys from vault
    pub vault_get_key_url: String,
    pub is_require_sign: bool,
}

/// Token management configuration
#[derive(Debug, Deserialize, Clone)]
pub struct TokenManagement {
    /// JKU (JWK Set URL) value
    pub jku: String,
    /// Key ID
    pub kid: String,
    /// Token existence time in milliseconds
    pub exist_time: u128,
    /// Token issuer
    pub iss: String,
    /// EAT profile identifier
    pub eat_profile: String,
    /// Is it enabled to send token information to MQ
    pub mq_enabled: bool,
    /// Send token information to MQ's topic
    pub token_topic: String,
}

/// Cert configuration
#[derive(Debug, Deserialize, Clone)]
pub struct Cert {
    /// Single user cert limit
    pub single_user_cert_limit: u64,
}

impl ServerConfig {
    /// Validates the configuration values
    /// 
    /// # Panics
    /// 
    /// Panics if nonce_bytes is not within the range of 64-1024
    pub fn validate(&self) {
        // Validate nonce_bytes is within the range of 64-1024
        let nonce_bytes = self.attestation_service.nonce.nonce_bytes;
        if nonce_bytes < 64 || nonce_bytes > 1024 {
            panic!("Invalid configuration: nonce_bytes must be between 64 and 1024, got {}", nonce_bytes);
        }
    }
}

/// Global configuration singleton instance
///
/// This provides direct access to the configuration singleton for the server.
/// Users should call `CONFIG.initialize(path)` to load the configuration and
/// `CONFIG.get_instance()` to access the loaded configuration.
pub static CONFIG: ConfigSingleton<ServerConfig> = ConfigSingleton::new();
