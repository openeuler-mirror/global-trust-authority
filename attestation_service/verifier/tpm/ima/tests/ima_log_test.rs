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

use tpm_ima_verifier::ImaLog;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[test]
fn test_ima_log_creation_from_valid_data() {
    // Create a simple valid IMA log string
    let log_str = "10 be00517f0f1e46f33a39e0a2c21f8f0ae681c647 ima-ng sha256:0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a boot_aggregate";
    let encoded_log = BASE64.encode(log_str);
    
    // Parse the log
    let ima_log = ImaLog::new(&encoded_log).expect("Failed to parse valid IMA log");
    
    // Verify the parsed log
    assert_eq!(ima_log.logs.len(), 1);
    let entry = &ima_log.logs[0];
    assert_eq!(entry.pcr_index, 10);
    assert_eq!(entry.template_hash, "be00517f0f1e46f33a39e0a2c21f8f0ae681c647");
    assert_eq!(entry.template_name, "ima-ng");
    assert_eq!(entry.file_hash_alg, "sha256");
    assert_eq!(entry.file_hash, "0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a");
    assert_eq!(entry.file_path, "boot_aggregate");
    assert_eq!(entry.ref_value_matched, None);
}

#[test]
fn test_ima_log_creation_from_invalid_data() {
    // Test with invalid base64
    let result = ImaLog::new("invalid-base64");
    assert!(result.is_err());
    
    // Test with invalid format (missing fields)
    let invalid_log = "10 be00517f0f1e46f33a39e0a2c21f8f0ae681c647 ima-ng";
    let encoded_invalid_log = BASE64.encode(invalid_log);
    let result = ImaLog::new(&encoded_invalid_log);
    assert!(result.is_err());
    
    // Test with invalid PCR index
    let invalid_pcr = "11 be00517f0f1e46f33a39e0a2c21f8f0ae681c647 ima-ng sha256:0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a boot_aggregate";
    let encoded_invalid_pcr = BASE64.encode(invalid_pcr);
    let result = ImaLog::new(&encoded_invalid_pcr);
    assert!(result.is_err());
    
    // Test with invalid hash format
    let invalid_hash = "10 be00517f0f1e46f33a39e0a2c21f8f0ae681c647 ima-ng sha256-0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a boot_aggregate";
    let encoded_invalid_hash = BASE64.encode(invalid_hash);
    let result = ImaLog::new(&encoded_invalid_hash);
    assert!(result.is_err());
}

#[test]
fn test_ima_log_to_json_value() {
    // Create a simple valid IMA log
    let log_str = "10 be00517f0f1e46f33a39e0a2c21f8f0ae681c647 ima-ng sha256:0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a boot_aggregate";
    let encoded_log = BASE64.encode(log_str);
    let ima_log = ImaLog::new(&encoded_log).expect("Failed to parse valid IMA log");
    
    // Convert to JSON
    let json_value = ima_log.to_json_value().expect("Failed to convert to JSON");
    
    // Verify JSON structure
    assert!(json_value.is_object());
    let logs = json_value.get("logs").expect("Missing logs field");
    assert!(logs.is_array());
    assert_eq!(logs.as_array().unwrap().len(), 1);
    
    let entry = &logs.as_array().unwrap()[0];
    assert_eq!(entry.get("pcr_index").unwrap().as_u64().unwrap(), 10);
    assert_eq!(entry.get("template_hash").unwrap().as_str().unwrap(), "be00517f0f1e46f33a39e0a2c21f8f0ae681c647");
    assert_eq!(entry.get("template_name").unwrap().as_str().unwrap(), "ima-ng");
    assert_eq!(entry.get("file_hash_alg").unwrap().as_str().unwrap(), "sha256");
    assert_eq!(entry.get("file_hash").unwrap().as_str().unwrap(), "0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a");
    assert_eq!(entry.get("file_path").unwrap().as_str().unwrap(), "boot_aggregate");
    assert!(entry.get("ref_value_matched").unwrap().is_null());
}

#[test]
fn test_multiple_ima_log_entries() {
    // Create a log with multiple entries
    let log_str = "10 be00517f0f1e46f33a39e0a2c21f8f0ae681c647 ima-ng sha256:0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a boot_aggregate\n\
                 10 abcdef1234567890abcdef1234567890abcdef12 ima-ng sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 /bin/bash";
    let encoded_log = BASE64.encode(log_str);
    
    // Parse the log
    let ima_log = ImaLog::new(&encoded_log).expect("Failed to parse valid IMA log");
    
    // Verify the parsed log
    assert_eq!(ima_log.logs.len(), 2);
    
    // Check first entry
    let entry1 = &ima_log.logs[0];
    assert_eq!(entry1.pcr_index, 10);
    assert_eq!(entry1.template_hash, "be00517f0f1e46f33a39e0a2c21f8f0ae681c647");
    assert_eq!(entry1.file_path, "boot_aggregate");
    
    // Check second entry
    let entry2 = &ima_log.logs[1];
    assert_eq!(entry2.pcr_index, 10);
    assert_eq!(entry2.template_hash, "abcdef1234567890abcdef1234567890abcdef12");
    assert_eq!(entry2.file_path, "/bin/bash");
}
