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

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use plugin_manager::ServiceHostFunctions;
use tpm_common_verifier::PcrValues;
use tpm_dim_verifier::measurement_log::{DimLog, DimLogEntry, HashAlgorithm};
use hex;
use openssl::hash::{Hasher, MessageDigest};

/// Test fixtures for DIM log tests
pub mod fixtures {
    use super::*;

    /// DIM specific PCR indices
    pub const DIM_PCR_START: u32 = 12;
    pub const DIM_PCR_END: u32 = 15;

    /// Calculate template hash according to DIM specification
    /// Matches the C implementation in DIM source code:
    /// template hash = hash(
    ///     "file hash algorithm string size + file digest size"
    ///     + "file hash algorithm string"
    ///     + "file digest"
    ///     + "file path string size"
    ///     + "file path"
    /// )
    pub fn calculate_template_hash(file_hash: &str, file_path: &str, _pcr_index: u32) -> String {
        let algo_name = "sha256";
        let file_hash_bytes = hex::decode(file_hash).expect("Invalid file hash hex format");
        
        // Calculate size1: algorithm name length + ":" length + 1 + digest size
        let size1 = (algo_name.len() + 1 + 1 + file_hash_bytes.len()) as u32;

        let mut hasher = Hasher::new(MessageDigest::sha256()).expect("Failed to create hasher");

        // Update hash with all components in order:
        // 1. size1 (little endian)
        hasher.update(&size1.to_le_bytes()).expect("Failed to update hash");
        // 2. algorithm name
        hasher.update(algo_name.as_bytes()).expect("Failed to update hash");
        // 3. ":" + "\0"
        hasher.update(b":\0").expect("Failed to update hash");
        // 4. file hash bytes
        hasher.update(&file_hash_bytes).expect("Failed to update hash");

        // Calculate size2: file path length + 1 (for "\0")
        let size2 = (file_path.len() + 1) as u32;
        // 5. size2 (little endian)
        hasher.update(&size2.to_le_bytes()).expect("Failed to update hash");
        // 6. file path + "\0"
        hasher.update(file_path.as_bytes()).expect("Failed to update hash");
        hasher.update(b"\0").expect("Failed to update hash");

        hex::encode(hasher.finish().expect("Failed to finalize hash"))
    }

    /// Calculate PCR value using TPM PCR extension
    pub fn calculate_pcr_value(initial_value: &str, template_hash: &str) -> String {
        let mut hasher = Hasher::new(MessageDigest::sha256()).expect("Failed to create hasher");
        hasher.update(&hex::decode(initial_value).expect("Invalid hex initial value")).expect("Failed to update hash");
        hasher.update(&hex::decode(template_hash).expect("Invalid hex template hash")).expect("Failed to update hash");
        hex::encode(hasher.finish().expect("Failed to finalize hash"))
    }

    /// Creates a valid DIM log entry for testing
    pub fn create_valid_log_entry() -> DimLogEntry {
        let file_path = "/boot/vmlinuz";
        let file_hash = "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969";
        let pcr_index = DIM_PCR_START;
        let template_hash = calculate_template_hash(file_hash, file_path, pcr_index);
        
        DimLogEntry {
            pcr_index,
            template_hash,
            file_hash_alg: HashAlgorithm::Sha256,
            file_hash: file_hash.to_string(),
            file_path: file_path.to_string(),
            log_type: "kernel".to_string(),
            ref_value_matched: None,
        }
    }

    /// Creates a valid PCR values instance for testing
    pub fn create_valid_pcr_values() -> PcrValues {
        let mut pcr_values = PcrValues::new();
        pcr_values.hash_alg = "sha256".to_string();
        // Initialize DIM PCRs with their initial values
        for pcr_index in DIM_PCR_START..=DIM_PCR_END {
            let initial_value = PcrValues::create_initial_pcr_value("sha256", pcr_index, None)
                .expect("Failed to create initial PCR value");
            pcr_values.set_pcr_value(pcr_index, initial_value.clone());
            pcr_values.update_replay_value(pcr_index, initial_value);
        }
        pcr_values
    }

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
}

/// Tests for DIM log parsing functionality
mod log_parsing_tests {
    use super::*;

    #[test]
    fn should_parse_valid_log_line() {
        // Arrange
        let line = "12 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969 sha256:3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969 /boot/vmlinuz [kernel]";
        
        // Act
        let parsed = DimLog::parse_log_line(line).expect("Failed to parse valid log line");
        
        // Assert
        assert_eq!(parsed.pcr_index, 12, "PCR index should match");
        assert_eq!(parsed.log_entry.file_path, "/boot/vmlinuz", "File path should match");
        assert_eq!(parsed.log_entry.log_type, "kernel", "Log type should match");
        assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256, "Hash algorithm should match");
    }

    #[test]
    fn should_fail_to_parse_invalid_log_line() {
        // Arrange
        let line = "12 0123456789abcdef sha256:abcdef /boot/vmlinuz [kernel]";
        
        // Act
        let result = DimLog::parse_log_line(line);
        
        // Assert
        assert!(result.is_err(), "Should fail to parse invalid log line");
    }

    #[test]
    fn should_fail_to_parse_log_with_invalid_pcr_index() {
        // Arrange
        let line = "24 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef /boot/vmlinuz [kernel]";
        
        // Act
        let result = DimLog::parse_log_line(line);
        
        // Assert
        assert!(result.is_err(), "Should fail to parse log with invalid PCR index");
    }

    #[test]
    fn should_fail_to_parse_log_with_invalid_hash_algorithm() {
        // Arrange
        let line = "12 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef invalid:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef /boot/vmlinuz [kernel]";
        
        // Act
        let result = DimLog::parse_log_line(line);
        
        // Assert
        assert!(result.is_err(), "Should fail to parse log with invalid hash algorithm");
    }
}

/// Tests for baseline log parsing
mod baseline_log_tests {
    use super::*;

    #[test]
    fn should_parse_static_baseline_log() {
        // Arrange
        let line = "0 e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e sha256:02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989 /opt/dim/demo/dim_test_demo [static_baseline]";
        
        // Act
        let parsed = DimLog::parse_log_line(line).expect("Failed to parse static baseline log");
        
        // Assert
        assert_eq!(parsed.pcr_index, 0, "PCR index should match");
        assert_eq!(parsed.log_entry.file_path, "/opt/dim/demo/dim_test_demo", "File path should match");
        assert_eq!(parsed.log_entry.log_type, "static_baseline", "Log type should match");
        assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256, "Hash algorithm should match");
        assert_eq!(parsed.log_entry.template_hash, "e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e", "Template hash should match");
        assert_eq!(parsed.log_entry.file_hash, "02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989", "File hash should match");
    }

    #[test]
    fn should_parse_dynamic_baseline_log() {
        // Arrange
        let line = "0 c1b0d9909ddb00633fc6bbe7e457b46b57e165166b8422e81014bdd3e6862899 sha256:35494ed41109ebc9bf9bf7b1c190b7e890e2f7ce62ca1920397cd2c02a057796 dim_core.text [dynamic_baseline]";
        
        // Act
        let parsed = DimLog::parse_log_line(line).expect("Failed to parse dynamic baseline log");
        
        // Assert
        assert_eq!(parsed.pcr_index, 0, "PCR index should match");
        assert_eq!(parsed.log_entry.file_path, "dim_core.text", "File path should match");
        assert_eq!(parsed.log_entry.log_type, "dynamic_baseline", "Log type should match");
        assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256, "Hash algorithm should match");
        assert_eq!(parsed.log_entry.template_hash, "c1b0d9909ddb00633fc6bbe7e457b46b57e165166b8422e81014bdd3e6862899", "Template hash should match");
        assert_eq!(parsed.log_entry.file_hash, "35494ed41109ebc9bf9bf7b1c190b7e890e2f7ce62ca1920397cd2c02a057796", "File hash should match");
    }

    #[test]
    fn should_parse_no_static_baseline_log() {
        // Arrange
        let line = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e ext4 [no_static_baseline]";
        
        // Act
        let parsed = DimLog::parse_log_line(line).expect("Failed to parse no static baseline log");
        
        // Assert
        assert_eq!(parsed.pcr_index, 0, "PCR index should match");
        assert_eq!(parsed.log_entry.file_path, "ext4", "File path should match");
        assert_eq!(parsed.log_entry.log_type, "no_static_baseline", "Log type should match");
        assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256, "Hash algorithm should match");
        assert_eq!(parsed.log_entry.template_hash, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "Template hash should match");
        assert_eq!(parsed.log_entry.file_hash, "db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e", "File hash should match");
    }
}

/// Tests for DIM log creation and conversion
mod log_creation_tests {
    use super::*;

    #[test]
    fn should_create_dim_log_with_mixed_states() {
        // Arrange
        let log_content = "0 e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e sha256:02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989 /opt/dim/demo/dim_test_demo [static_baseline]\n\
0 08a2f6f2922ad3d1cf376ae05cf0cc507c2f5a1c605adf445506bc84826531d6 sha256:855ec9a890ff22034f7e13b78c2089e28e8d217491665b39203b50ab47b111c8 /opt/dim/demo/dim_test_demo [tampered]";
        let log_data = BASE64.encode(log_content);
        
        // Act
        let dim_log = DimLog::new(&log_data).expect("Failed to create DIM log with mixed states");
        
        // Assert
        assert!(!dim_log.logs.is_empty(), "Logs should not be empty");
        assert!(dim_log.logs.contains_key(&0), "Should contain PCR index 0");
        
        let entries = dim_log.logs.get(&0).expect("Should get entries for PCR index 0");
        assert_eq!(entries.len(), 2, "Should have 2 entries");
        
        // Verify static baseline entry
        let baseline_entry = entries.iter().find(|e| e.log_type == "static_baseline")
            .expect("Should find static baseline entry");
        assert_eq!(baseline_entry.file_path, "/opt/dim/demo/dim_test_demo", "File path should match");
        assert_eq!(baseline_entry.template_hash, "e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e", "Template hash should match");
        assert_eq!(baseline_entry.file_hash, "02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989", "File hash should match");
        
        // Verify tampered entry
        let tampered_entry = entries.iter().find(|e| e.log_type == "tampered")
            .expect("Should find tampered entry");
        assert_eq!(tampered_entry.file_path, "/opt/dim/demo/dim_test_demo", "File path should match");
        assert_eq!(tampered_entry.template_hash, "08a2f6f2922ad3d1cf376ae05cf0cc507c2f5a1c605adf445506bc84826531d6", "Template hash should match");
        assert_eq!(tampered_entry.file_hash, "855ec9a890ff22034f7e13b78c2089e28e8d217491665b39203b50ab47b111c8", "File hash should match");
    }

    #[test]
    fn should_create_dim_log_from_base64() {
        // Arrange
        let log_content = "0 e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e sha256:02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989 /opt/dim/demo/dim_test_demo [static_baseline]";
        let log_data = BASE64.encode(log_content);
        
        // Act
        let dim_log = DimLog::new(&log_data).expect("Failed to create DIM log from base64");
        
        // Assert
        assert!(!dim_log.logs.is_empty(), "Logs should not be empty");
        assert!(dim_log.logs.contains_key(&0), "Should contain PCR index 0");
        
        let entries = dim_log.logs.get(&0).expect("Should get entries for PCR index 0");
        assert_eq!(entries.len(), 1, "Should have 1 entry");
        let entry = &entries[0];
        assert_eq!(entry.file_path, "/opt/dim/demo/dim_test_demo", "File path should match");
        assert_eq!(entry.log_type, "static_baseline", "Log type should match");
    }
}

/// Tests for PCR value replay and verification
mod pcr_verification_tests {
    use super::*;
    use crate::fixtures::{create_valid_pcr_values, create_mock_service_host_functions, calculate_template_hash, calculate_pcr_value, DIM_PCR_START};

    #[test]
    fn should_successfully_replay_pcr_values() {
        // Arrange
        let file_path = "test_file";
        let file_hash = "5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02";
        let pcr_index = DIM_PCR_START;
        let template_hash = calculate_template_hash(file_hash, file_path, pcr_index);
        let log_content = format!("{} {} sha256:{} {} [static baseline]", 
            pcr_index, template_hash, file_hash, file_path);
        let log_data = BASE64.encode(log_content);
        let dim_log = DimLog::new(&log_data).expect("Failed to create DIM log");
        let mut pcr_values = create_valid_pcr_values();
        let initial_value = pcr_values.get_pcr_value(pcr_index).expect("Should get initial PCR value");
        let expected_pcr = calculate_pcr_value(&initial_value, &template_hash);
        
        // Act
        let result = dim_log.replay_pcr_values(&mut pcr_values);
        
        // Assert
        assert!(result.is_ok(), "Should successfully replay PCR values");
        let actual_pcr = pcr_values.get_pcr_replay_value(pcr_index).unwrap().unwrap();
        assert_eq!(actual_pcr, expected_pcr, "PCR value should match expected value");
    }

    #[test]
    fn should_fail_when_template_hash_mismatches() {
        // Arrange
        let file_path = "ext4";
        let file_hash = "db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e";
        let pcr_index = DIM_PCR_START;
        let template_hash = calculate_template_hash(file_hash, file_path, pcr_index);
        let log_content = format!("{} {} sha256:{} {} [static_baseline]", 
            pcr_index, template_hash, file_hash, file_path);
        let log_data = BASE64.encode(log_content);
        let mut dim_log = DimLog::new(&log_data).expect("Failed to create DIM log");
        let mut pcr_values = create_valid_pcr_values();

        // Set an invalid PCR value (not matching the expected value)
        let wrong_pcr = "1".repeat(64);
        pcr_values.set_pcr_value(pcr_index, wrong_pcr);

        let service_host_functions = create_mock_service_host_functions();
        let user_id = "test_user";

        // Act
        let result = tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(dim_log.verify(&mut pcr_values, &service_host_functions, user_id));

        // Assert
        assert!(result.is_ok(), "Verification should not error");
        let matched = pcr_values.check_is_matched().unwrap();
        assert!(!matched, "Should fail PCR match when template hash mismatches");
    }

    #[test]
    fn should_verify_pcr_match() {
        // Arrange
        let file_path = "/boot/vmlinuz-5.15.0-56-generic";
        let file_hash = "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969";
        let pcr_index = DIM_PCR_START;
        let template_hash = calculate_template_hash(file_hash, file_path, pcr_index);
        let log_content = format!("{} {} sha256:{} {} [static baseline]", 
            pcr_index, template_hash, file_hash, file_path);
        let log_data = BASE64.encode(log_content);
        let mut dim_log = DimLog::new(&log_data).expect("Failed to create DIM log");
        let mut pcr_values = create_valid_pcr_values();
        
        // Set the expected PCR value
        let expected_pcr = "5c94a5d30f8407ca1bac9f76708cd85b69d77ec25814fddd40bed1a8dcfedee3";
        pcr_values.set_pcr_value(pcr_index, expected_pcr.to_string());
           
        let service_host_functions = create_mock_service_host_functions();
        let user_id = "test_user";
        
        // Act
        let result = tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(dim_log.verify(&mut pcr_values, &service_host_functions, user_id));
        
        // Assert
        assert!(result.is_ok(), "Verification should succeed");
        let matched = pcr_values.check_is_matched().unwrap();
        assert!(matched, "Should verify PCR match");
    }
}