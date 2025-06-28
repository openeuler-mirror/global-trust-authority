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

use base64::Engine;
use plugin_manager::{ServiceHostFunctions, ServicePlugin};
use tpm_common_verifier::{GenerateEvidence, Logs, PcrValues};
use tpm_dim_verifier::verifier::TpmDimPlugin;

/// Test fixtures and utilities for TPM DIM verifier tests
mod fixtures {
    use super::*;

    /// Creates a mock service host functions instance for testing
    pub fn create_mock_service_host_functions() -> ServiceHostFunctions {
        ServiceHostFunctions {
            get_unmatched_measurements: Box::new(|_file_hashes, _attester_type, _user_id| {
                Box::pin(async { Ok(Vec::new()) })
            }),
            query_configuration: |_key| None,
            validate_cert_chain: Box::new(|_plugin_type, _user_id, _cert_chain| Box::pin(async { true })),
        }
    }

    /// Creates a mock TPM DIM plugin for testing
    pub fn create_mock_plugin() -> TpmDimPlugin {
        TpmDimPlugin::new("tpm_dim".to_string(), create_mock_service_host_functions())
    }

    /// Creates a valid PCR values instance for testing
    pub fn create_valid_pcr_values() -> PcrValues {
        let mut pcr_values = PcrValues::new();
        pcr_values.hash_alg = "sha256".to_string();
        let initial_value = PcrValues::create_initial_pcr_value("sha256", 0, None)
            .expect("Failed to create initial PCR value");
        pcr_values.set_pcr_value(0, initial_value);
        pcr_values
    }

    /// Creates a valid log entry for testing
    pub fn create_valid_log_entry() -> Logs {
        let log_content = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
            sha256:5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02 \
            test_file [static baseline]";
        let log_data = base64::engine::general_purpose::STANDARD.encode(log_content);
        Logs { log_type: "tpm_dim".to_string(), log_data }
    }
}

/// Tests for evidence generation functionality
mod evidence_generation_tests {
    use super::*;

    #[tokio::test]
    async fn should_generate_evidence_successfully() {
        // Arrange
        let plugin = fixtures::create_mock_plugin();
        let mut pcr_values = fixtures::create_valid_pcr_values();
        let logs = vec![fixtures::create_valid_log_entry()];

        // Act
        let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;

        // Assert
        assert!(result.is_ok(), "Should generate evidence successfully");
        let json = result.unwrap();
        assert!(json.is_object(), "Generated evidence should be a JSON object");
    }

    #[tokio::test]
    async fn should_fail_with_empty_logs() {
        // Arrange
        let plugin = fixtures::create_mock_plugin();
        let mut pcr_values = fixtures::create_valid_pcr_values();
        let logs: Vec<Logs> = vec![];

        // Act
        let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;

        // Assert
        assert!(result.is_err(), "Should fail with empty logs");
    }

    #[tokio::test]
    async fn should_fail_with_multiple_logs() {
        // Arrange
        let plugin = fixtures::create_mock_plugin();
        let mut pcr_values = fixtures::create_valid_pcr_values();
        let logs = vec![
            fixtures::create_valid_log_entry(),
            fixtures::create_valid_log_entry(),
        ];

        // Act
        let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;

        // Assert
        assert!(result.is_err(), "Should fail with multiple logs");
    }

    #[tokio::test]
    async fn should_fail_with_invalid_log_type() {
        // Arrange
        let plugin = fixtures::create_mock_plugin();
        let mut pcr_values = fixtures::create_valid_pcr_values();
        let mut log_entry = fixtures::create_valid_log_entry();
        log_entry.log_type = "invalid_type".to_string();
        let logs = vec![log_entry];

        // Act
        let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;

        // Assert
        assert!(result.is_err(), "Should fail with invalid log type");
    }
}

/// Tests for evidence verification functionality
mod evidence_verification_tests {
    use super::*;

    #[tokio::test]
    async fn should_fail_to_verify_invalid_json() {
        // Arrange
        let plugin = fixtures::create_mock_plugin();
        let invalid_json = serde_json::json!({ "invalid": "data" });

        // Act
        let result = plugin.verify_evidence("test_user", None, &invalid_json, None).await;

        // Assert
        assert!(result.is_err(), "Should fail to verify invalid JSON");
    }
}
