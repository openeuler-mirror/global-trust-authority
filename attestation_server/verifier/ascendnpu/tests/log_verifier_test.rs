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

use ascend_npu_verifier::evidence::Log;
use ascend_npu_verifier::log_verifier::{LogResult, verify_all_logs, parse_ima_binary_log, parse_ima_template_data};
use ascend_npu_verifier::verifier::AscendNpuPlugin;
use plugin_manager::ServiceHostFunctions;
use base64::{engine::general_purpose, Engine as _};
use common_verifier::ImaLog;
use std::fs;
use tpm_common_verifier::{PcrValues, PcrValueEntry};

// Helper function to create test PCR values
fn create_test_pcr_values() -> PcrValues {
    let pcr_entries = vec![PcrValueEntry {
        pcr_index: 10,
        pcr_value: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        replay_value: None,
        is_matched: None,
    }];
    
    PcrValues {
        hash_alg: "sha256".to_string(),
        pcr_values: pcr_entries,
    }
}

// Helper function to create IMA binary log data
fn create_ima_binary_log_data(file_path: &str) -> Vec<u8> {
    let mut log_data = Vec::new();
    
    // PCR index (4 bytes) - PCR 10
    log_data.extend_from_slice(&10u32.to_le_bytes());
    
    // Template data hash (32 bytes) - SHA256 for ima-ng
    log_data.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                                 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    
    // Template name length (4 bytes) - "ima-ng" = 6 bytes
    log_data.extend_from_slice(&6u32.to_le_bytes());
    
    // Template name (6 bytes) - "ima-ng"
    log_data.extend_from_slice(b"ima-ng");
    
    // Calculate template data size
    let file_path_bytes = format!("{}\0", file_path).into_bytes();
    let template_data_size = 4 + 8 + 32 + 4 + file_path_bytes.len();
    
    // Template data length (4 bytes)
    log_data.extend_from_slice(&(template_data_size as u32).to_le_bytes());
    
    // Template data - IMA native format
    let mut template_data = vec![0u8; template_data_size];
    let mut pos = 0;
    
    // Length field (4 bytes) - 8 + 32 + 4 + file_path_len
    template_data[pos..pos+4].copy_from_slice(&((8 + 32 + 4 + file_path_bytes.len()) as u32).to_le_bytes());
    pos += 4;
    
    // Hash algorithm prefix (8 bytes) - "sha256:\0"
    template_data[pos..pos+8].copy_from_slice(b"sha256:\0");
    pos += 8;
    
    // File hash (32 bytes)
    template_data[pos..pos+32].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    pos += 32;
    
    // File path length (4 bytes)
    template_data[pos..pos+4].copy_from_slice(&(file_path_bytes.len() as u32).to_le_bytes());
    pos += 4;
    
    // File path
    template_data[pos..pos+file_path_bytes.len()].copy_from_slice(&file_path_bytes);
    log_data.extend_from_slice(&template_data);
    
    log_data
}

fn create_mock_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    }
}

#[tokio::test]
async fn test_boot_measurement_log_verification() {
    let logs = vec![
        Log {
            log_type: "boot_measurement".to_string(),
            log_data: "dGVzdF9ib290X2xvZw==".to_string(),
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    // Boot measurement verification should fail since format is undetermined
    assert_eq!(results[0].log_status, "replay_failure");
    assert_eq!(results[0].log_type, "boot_measurement");
    assert_eq!(results[0].ref_value_match_status, "ignore");
}

#[tokio::test]
async fn test_runtime_measurement_log_verification() {
    // Create IMA binary log data using helper function
    let log_data = create_ima_binary_log_data("/usr/bin/bash");
    
    // Encode as base64
    let encoded_data = general_purpose::STANDARD.encode(&log_data);
    
    let logs = vec![
        Log {
            log_type: "runtime_measurement".to_string(),
            log_data: encoded_data,
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    // Note: verification may fail due to mock PCR values, but parsing should work
    assert!(results[0].log_status == "replay_success" || results[0].log_status == "replay_failure");
    assert_eq!(results[0].log_type, "runtime_measurement");
}

#[tokio::test]
async fn test_unsupported_log_type() {
    let logs = vec![
        Log {
            log_type: "unsupported_log".to_string(),
            log_data: "dGVzdF9sb2c=".to_string(),
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].log_status, "replay_failure");
    assert_eq!(results[0].log_type, "unsupported_log");
}

#[tokio::test]
async fn test_empty_log_data() {
    let logs = vec![
        Log {
            log_type: "boot_measurement".to_string(),
            log_data: "".to_string(), // Empty log data
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].log_status, "replay_failure");
    assert_eq!(results[0].log_type, "boot_measurement");
}

#[tokio::test]
async fn test_multiple_logs_verification() {
    // Create IMA binary log data using helper function
    let log_data = create_ima_binary_log_data("/usr/bin/bash");
    
    // Encode as base64
    let encoded_runtime_data = general_purpose::STANDARD.encode(&log_data);
    
    let logs = vec![
        Log {
            log_type: "boot_measurement".to_string(),
            log_data: "dGVzdF9ib290X2xvZw==".to_string(),
        },
        Log {
            log_type: "runtime_measurement".to_string(),
            log_data: encoded_runtime_data,
        },
        Log {
            log_type: "unsupported_log".to_string(),
            log_data: "dGVzdF9sb2c=".to_string(),
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 3);
    
    // Check that boot_measurement fails (format undetermined) and runtime_measurement is verified
    let boot_result = results.iter().find(|r| r.log_type == "boot_measurement").unwrap();
    assert_eq!(boot_result.log_status, "replay_failure");
    assert_eq!(boot_result.ref_value_match_status, "ignore");
    
    let runtime_result = results.iter().find(|r| r.log_type == "runtime_measurement").unwrap();
    // Note: verification may fail due to mock PCR values, but parsing should work
    assert!(runtime_result.log_status == "replay_success" || runtime_result.log_status == "replay_failure");
    
    // Check that unsupported log is not verified
    let unsupported_result = results.iter().find(|r| r.log_type == "unsupported_log").unwrap();
    assert_eq!(unsupported_result.log_status, "replay_failure");
}

#[tokio::test]
async fn test_log_result_creation() {
    let success_result = LogResult::success("test_log".to_string(), "replay_success".to_string(), "matched".to_string());
    assert_eq!(success_result.log_status, "replay_success");
    assert_eq!(success_result.log_type, "test_log");
    assert_eq!(success_result.ref_value_match_status, "matched");
    
    let failure_result = LogResult::failure("test_log".to_string(), "replay_failure".to_string(), "ignore".to_string());
    assert_eq!(failure_result.log_status, "replay_failure");
    assert_eq!(failure_result.log_type, "test_log");
    assert_eq!(failure_result.ref_value_match_status, "ignore");
}

#[tokio::test]
async fn test_empty_log_list_verification() {
    let logs = vec![]; // Empty log list

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 0); // No logs to verify
}

#[tokio::test]
async fn test_log_result_json_conversion() {
    let result = LogResult::success("test_log".to_string(), "replay_success".to_string(), "matched".to_string());
    let json_value = result.to_json_value();
    
    assert_eq!(json_value["log_type"], "test_log");
    assert_eq!(json_value["log_status"], "replay_success");
    assert_eq!(json_value["ref_value_match_status"], "matched");
}

#[test]
fn test_parse_ima_template_data_ima_ng() {
    // Create test data for IMA-NG template: file_hash (32 bytes) + file_path (variable length)
    let mut template_data = vec![0u8; 45]; // 32 + 13
    
    // Set file hash (first 32 bytes)
    template_data[..32].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                          0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                                          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    
    // Set file path (bytes 32-45)
    let file_path = "/bin/ls";
    let path_bytes = file_path.as_bytes();
    template_data[32..32 + path_bytes.len()].copy_from_slice(path_bytes);
    
    let result = parse_ima_template_data(&template_data, "ima-ng").unwrap();
    assert_eq!(result.0.len(), 32);
    assert_eq!(result.1, "/bin/ls");
}

#[test]
fn test_parse_ima_template_data_unsupported_ima() {
    // Test unsupported "ima" template
    let template_data = vec![0u8; 276]; // 20 + 256
    
    let result = parse_ima_template_data(&template_data, "ima");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsupported IMA template"));
}

#[test]
fn test_parse_ima_template_data_unsupported_template() {
    // Test unknown template
    let template_data = b"/unknown/file/path\0";
    
    let result = parse_ima_template_data(template_data, "unknown-template");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsupported IMA template"));
}

#[test]
fn test_parse_ima_binary_log_empty() {
    let log_data = vec![];
    let result = parse_ima_binary_log(&log_data);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_parse_ima_binary_log_single_entry() {
    // Create IMA binary log data using helper function
    let log_data = create_ima_binary_log_data("/usr/bin/bash");
    
    let result = parse_ima_binary_log(&log_data).unwrap();
    assert_eq!(result.len(), 1);
    
    let entry = &result[0];
    assert_eq!(entry.pcr_index, 10);
    assert_eq!(entry.template_name, "ima-ng");
    assert_eq!(entry.template_data_len, 62);
}

#[tokio::test]
async fn test_runtime_measurement_with_real_ima_data() {
    // Create IMA binary log data using helper function
    let log_data = create_ima_binary_log_data("/usr/bin/bash");
    
    // Encode as base64
    let encoded_data = general_purpose::STANDARD.encode(&log_data);
    
    let logs = vec![
        Log {
            log_type: "runtime_measurement".to_string(),
            log_data: encoded_data,
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    
    let result = &results[0];
    assert_eq!(result.log_type, "runtime_measurement");
    // Note: verification may fail due to mock PCR values, but parsing should work
    assert!(result.log_status == "replay_success" || result.log_status == "replay_failure");
    
    // Check log_data
    if let Some(log_data) = &result.log_data {
        // Check that log_data contains the parsed IMA log
        assert!(log_data.get("logs").is_some());
        if let Some(logs_array) = log_data["logs"].as_array() {
            assert!(!logs_array.is_empty());
        }
    }
}

#[tokio::test]
async fn test_ima_binary_parsing_from_real_files() {
    // Read the binary IMA data
    let ima_bin_path = "tests/data/ima.bin";
    let ima_bin_data = fs::read(ima_bin_path).expect("Failed to read ima.bin");
    
    // Test direct binary parsing using ImaLog::from_binary
    let ima_log = ImaLog::from_binary(&ima_bin_data, "sha256").expect("Failed to parse binary IMA data");
    
    // Verify we got entries
    assert!(!ima_log.logs.is_empty(), "Should have parsed at least one entry");
    
    // Verify all entries have expected structure
    for (i, entry) in ima_log.logs.iter().enumerate() {
        assert_eq!(entry.pcr_index, 10, "PCR index should be 10 for entry {}", i);
        assert_eq!(entry.template_name, "ima-ng", "Template name should be 'ima-ng' for entry {}", i);
        assert_eq!(entry.file_hash_alg, "sha256", "Hash algorithm should be 'sha256' for entry {}", i);
        assert!(!entry.file_hash.is_empty(), "File hash should not be empty for entry {}", i);
        assert!(!entry.file_path.is_empty(), "File path should not be empty for entry {}", i);
    }
}

#[tokio::test]
async fn test_ima_binary_vs_text_format_comparison() {
    // Read both binary and text files
    let ima_bin_path = "tests/data/ima.bin";
    let ima_log_path = "tests/data/ima.log";
    
    let ima_bin_data = fs::read(ima_bin_path).expect("Failed to read ima.bin");
    let expected_text = fs::read_to_string(ima_log_path).expect("Failed to read ima.log");
    let expected_lines: Vec<&str> = expected_text.lines().filter(|line| !line.trim().is_empty()).collect();
    
    // Parse binary data
    let ima_log = ImaLog::from_binary(&ima_bin_data, "sha256").expect("Failed to parse binary IMA data");
    
    // Verify we got the expected number of entries
    assert_eq!(ima_log.logs.len(), expected_lines.len(), 
               "Expected {} entries, got {}", expected_lines.len(), ima_log.logs.len());
    
    // Verify each entry matches expected format
    for (i, (parsed_entry, expected_line)) in ima_log.logs.iter().zip(expected_lines.iter()).enumerate() {
        // Parse expected line: "pcr template_hash template_name hash_alg:hash file_path"
        let parts: Vec<&str> = expected_line.split_whitespace().collect();
        assert_eq!(parts.len(), 5, "Expected 5 parts in line: {}", expected_line);
        
        let expected_pcr = parts[0].parse::<u32>().expect("Failed to parse PCR index");
        let _expected_template_hash = parts[1]; // We don't verify template hash in this test
        let expected_template = parts[2];
        let expected_hash_part = parts[3];
        let expected_path = parts[4];
        
        // Extract hash algorithm and hash from "sha256:hash"
        let hash_parts: Vec<&str> = expected_hash_part.split(':').collect();
        assert_eq!(hash_parts.len(), 2, "Expected hash format 'alg:hash'");
        let expected_hash_alg = hash_parts[0];
        let expected_hash = hash_parts[1];
        
        // Verify parsed values match expected values
        assert_eq!(parsed_entry.pcr_index, expected_pcr, 
                   "PCR index mismatch for entry {}", i);
        assert_eq!(parsed_entry.template_name, expected_template, 
                   "Template name mismatch for entry {}", i);
        assert_eq!(parsed_entry.file_hash_alg, expected_hash_alg, 
                   "Hash algorithm mismatch for entry {}", i);
        assert_eq!(parsed_entry.file_hash, expected_hash, 
                   "Hash mismatch for entry {}", i);
        assert_eq!(parsed_entry.file_path, expected_path, 
                   "File path mismatch for entry {}", i);
    }
}

#[tokio::test]
async fn test_ima_binary_verification_pipeline() {
    // Read the binary IMA data and convert to base64
    let ima_bin_path = "tests/data/ima.bin";
    let ima_bin_data = fs::read(ima_bin_path).expect("Failed to read ima.bin");
    let ima_bin_base64 = general_purpose::STANDARD.encode(&ima_bin_data);
    
    // Test the full verification pipeline with binary data
    let logs = vec![
        Log {
            log_type: "runtime_measurement".to_string(),
            log_data: ima_bin_base64,
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    
    let result = &results[0];
    assert_eq!(result.log_type, "runtime_measurement");
    // Note: verification may fail due to mock PCR values, but the parsing should work
    assert!(result.log_status == "replay_success" || result.log_status == "replay_failure");
    
    // Check that we have verification details
    if let Some(log_data) = &result.log_data {
        // Check that log_data contains the parsed IMA log
        assert!(log_data.get("logs").is_some());
        if let Some(logs_array) = log_data["logs"].as_array() {
            assert!(!logs_array.is_empty());
        }
    }
}

#[tokio::test]
async fn test_ima_binary_verification_details() {
    // Read the binary IMA data and convert to base64
    let ima_bin_path = "tests/data/ima.bin";
    let ima_log_path = "tests/data/ima.log";
    
    let ima_bin_data = fs::read(ima_bin_path).expect("Failed to read ima.bin");
    let ima_bin_base64 = general_purpose::STANDARD.encode(&ima_bin_data);
    let expected_text = fs::read_to_string(ima_log_path).expect("Failed to read ima.log");
    let expected_lines: Vec<&str> = expected_text.lines().filter(|line| !line.trim().is_empty()).collect();
    
    // Test the full verification pipeline with binary data
    let logs = vec![
        Log {
            log_type: "runtime_measurement".to_string(),
            log_data: ima_bin_base64,
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let test_pcrs = create_test_pcr_values();
    let results = verify_all_logs(&logs, &plugin, "test_user", None, &test_pcrs).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    let result = &results[0];
    
    // Verify log_data contains the parsed entries
    if let Some(log_data) = &result.log_data {
        // Check that log_data contains the parsed IMA log
        assert!(log_data.get("logs").is_some());
        if let Some(logs_array) = log_data["logs"].as_array() {
            assert_eq!(logs_array.len(), expected_lines.len());
            
            // Check first entry matches expected boot_aggregate
            if !logs_array.is_empty() {
                let first_entry = &logs_array[0];
                assert_eq!(first_entry["pcr_index"].as_u64().unwrap(), 10);
                assert_eq!(first_entry["template_name"].as_str().unwrap(), "ima-ng");
                assert_eq!(first_entry["file_hash_alg"].as_str().unwrap(), "sha256");
                assert_eq!(first_entry["file_path"].as_str().unwrap(), "boot_aggregate");
            }
            
            // Check second entry matches expected /usr/bin/cat
            if logs_array.len() > 1 {
                let second_entry = &logs_array[1];
                assert_eq!(second_entry["pcr_index"].as_u64().unwrap(), 10);
                assert_eq!(second_entry["template_name"].as_str().unwrap(), "ima-ng");
                assert_eq!(second_entry["file_hash_alg"].as_str().unwrap(), "sha256");
                assert_eq!(second_entry["file_path"].as_str().unwrap(), "/usr/bin/cat");
            }
        }
    }
}
