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

use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::ConfigSingleton;

/// Main configuration structure that matches the `server_config.yaml` file structure.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ServerConfig {
    /// Common configuration settings
    pub attestation_common: Option<AttestationCommon>,
    /// Service-specific configuration settings
    pub attestation_service: AttestationService,
}

/// Common configuration settings
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AttestationCommon {
    /// YAML parsing support information
    pub yaml_parse_support: String,
}

/// Nonce configuration settings
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct NonceConfig {
    /// Nonce valid period in seconds
    pub nonce_valid_period: u64,
    /// Nonce bytes
    pub nonce_bytes: u64
}

/// Plugin configuration
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Plugin {
    /// Plugin name
    pub name: String,
    /// Plugin path
    pub path: String,
}

/// Export policy file configuration
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ExportPolicyFile {
    /// Policy name
    pub name: String,
    /// Policy path
    pub path: String,
}

/// Policy configuration settings
#[derive(Debug, Deserialize, Clone, Serialize)]
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
#[derive(Debug, Deserialize, Clone, Serialize)]
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
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct KeyManagement {
    /// URL for retrieving signing keys from vault
    pub vault_get_key_url: String,
    pub is_require_sign: bool,
    pub key_ca_cert_path: String,
    pub key_cli_key_path: String,
    pub key_cli_cert_path: String,
}

/// Token management configuration
#[derive(Debug, Deserialize, Clone, Serialize)]
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
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Cert {
    /// Single user cert limit
    pub single_user_cert_limit: u64,
}

impl ServerConfig {
    /// Validates the configuration values
    /// 
    /// # Panics
    /// 
    /// Panics if `nonce_bytes` is not within the range of 64-1024
    /// Panics if any URL contains characters that could lead to log injection
    pub fn validate(&self) {
        // Validate nonce_bytes is within the range of 64-1024
        let nonce_bytes = self.attestation_service.nonce.nonce_bytes;
        if !(64..=1024).contains(&nonce_bytes) {
            panic!("Invalid configuration: nonce_bytes must be between 64 and 1024, got {}", nonce_bytes);
        }

        // Convert the config to a serde_json::Value to iterate over all string fields
        let config_value = serde_json::to_value(self).expect("Failed to convert config to JSON Value");
        Self::validate_all_strings_for_log_injection(&config_value, "root");
    }

    /// Recursively validates all string fields within a `serde_json::Value` for log injection characters.
    fn validate_all_strings_for_log_injection(value: &Value, path: &str) {
        match value {
            Value::String(s) => {
                Self::validate_string_for_log_injection(s, path);
            }
            Value::Object(map) => {
                for (key, val) in map {
                    Self::validate_all_strings_for_log_injection(val, &format!("{}.{}", path, key));
                }
            }
            Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    Self::validate_all_strings_for_log_injection(val, &format!("{}[{}]", path, i));
                }
            }
            _ => {},
        }
    }

    /// Validates if a string contains characters that could lead to log injection
    ///
    /// # Panics
    ///
    /// Panics if the string contains newlines, carriage returns, or other control characters
    fn validate_string_for_log_injection(text: &str, field_name: &str) {
        for (i, c) in text.chars().enumerate() {
            if c.is_control() && c != ' ' {
                panic!(
                    "Invalid configuration: {} contains dangerous character \'{}\' at position {}",
                    field_name,
                    c.escape_debug(),
                    i
                );
            }
        }
    }
}

/// Global configuration singleton instance
///
/// This provides direct access to the configuration singleton for the server.
/// Users should call `CONFIG.initialize(path)` to load the configuration and
/// `CONFIG.get_instance()` to access the loaded configuration.
pub static CONFIG: ConfigSingleton<ServerConfig> = ConfigSingleton::new();
