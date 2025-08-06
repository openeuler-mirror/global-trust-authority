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

use common_verifier::ImaLog;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[test]
fn test_ima_log_creation_from_valid_data_sha256() {
    // Create a simple valid IMA log string
    let log_str = "10 65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3 ima-ng sha256:0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f /usr/bin/kmod";
    let encoded_log = BASE64.encode(log_str);
    
    // Parse the log
    let ima_log = ImaLog::new(&encoded_log, "sha256").expect("Failed to parse valid IMA log");
    
    // Verify the parsed log
    assert_eq!(ima_log.logs.len(), 1);
    let entry = &ima_log.logs[0];
    assert_eq!(entry.pcr_index, 10);
    assert_eq!(entry.template_hash, "65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3");
    assert_eq!(entry.template_name, "ima-ng");
    assert_eq!(entry.file_hash_alg, "sha256");
    assert_eq!(entry.file_hash, "0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f");
    assert_eq!(entry.file_path, "/usr/bin/kmod");
    assert_eq!(entry.ref_value_matched, None);
}

#[test]
fn test_ima_log_creation_from_valid_data_sha1() {
    // Create a simple valid IMA log string
    let log_str = "10 16700c00f09fd3ed102739cd0c23018544ca1388 ima-ng sha256:0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f /usr/bin/kmod";
    let encoded_log = BASE64.encode(log_str);
    
    // Parse the log
    let ima_log = ImaLog::new(&encoded_log, "sha1").expect("Failed to parse valid IMA log");
    
    // Verify the parsed log
    assert_eq!(ima_log.logs.len(), 1);
    let entry = &ima_log.logs[0];
    assert_eq!(entry.pcr_index, 10);
    assert_eq!(entry.template_hash, "16700c00f09fd3ed102739cd0c23018544ca1388");
    assert_eq!(entry.template_name, "ima-ng");
    assert_eq!(entry.file_hash_alg, "sha256");
    assert_eq!(entry.file_hash, "0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f");
    assert_eq!(entry.file_path, "/usr/bin/kmod");
    assert_eq!(entry.ref_value_matched, None);
}

#[test]
fn test_ima_log_creation_from_invalid_data() {
    // Test with invalid base64
    let result = ImaLog::new("invalid-base64", "sha256");
    assert!(result.is_err());
    
    // Test with invalid format (missing fields)
    let invalid_log = "10 65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3 ima-ng";
    let encoded_invalid_log = BASE64.encode(invalid_log);
    let result = ImaLog::new(&encoded_invalid_log, "sha256");
    assert!(result.is_err());
    
    // Test with invalid hash format
    let invalid_hash = "10 65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3 ima-ng sha256-0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f /usr/bin/kmod";
    let encoded_invalid_hash = BASE64.encode(invalid_hash);
    let result = ImaLog::new(&encoded_invalid_hash, "sha256");
    assert!(result.is_err());
}

#[test]
fn test_ima_log_to_json_value() {
    // Create a simple valid IMA log
    let log_str = "10 65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3 ima-ng sha256:0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f /usr/bin/kmod";
    let encoded_log = BASE64.encode(log_str);
    let ima_log = ImaLog::new(&encoded_log, "sha256").expect("Failed to parse valid IMA log");
    
    // Convert to JSON
    let json_value = ima_log.to_json_value().expect("Failed to convert to JSON");
    
    // Verify JSON structure
    assert!(json_value.is_object());
    let logs = json_value.get("logs").expect("Missing logs field");
    assert!(logs.is_array());
    assert_eq!(logs.as_array().unwrap().len(), 1);
    
    let entry = &logs.as_array().unwrap()[0];
    assert_eq!(entry.get("pcr_index").unwrap().as_u64().unwrap(), 10);
    assert_eq!(entry.get("template_hash").unwrap().as_str().unwrap(), "65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3");
    assert_eq!(entry.get("template_name").unwrap().as_str().unwrap(), "ima-ng");
    assert_eq!(entry.get("file_hash_alg").unwrap().as_str().unwrap(), "sha256");
    assert_eq!(entry.get("file_hash").unwrap().as_str().unwrap(), "0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f");
    assert_eq!(entry.get("file_path").unwrap().as_str().unwrap(), "/usr/bin/kmod");
    assert!(entry.get("ref_value_matched").unwrap().is_null());
}

#[test]
fn test_multiple_ima_log_entries() {
    // Create a log with multiple entries
    let log_str = "11 65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3 ima-ng sha256:0f1f5e63a070f3519fa1cabc18646d001531e5c250443bd30739347c9be1069f /usr/bin/kmod\n\
                 10 d44df8df19bbb925d8a929bba30e2694bbd17abf9d14400c6fbfcd87c6d73065 ima-ng sha256:6c5e1b4528b704dc7081aa45b5037bda4ea9cad78ca562b4fb6b0dbdbfc7e7e7 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
    let encoded_log = BASE64.encode(log_str);
    
    // Parse the log
    let ima_log = ImaLog::new(&encoded_log, "sha256").expect("Failed to parse valid IMA log");
    
    // Verify the parsed log
    assert_eq!(ima_log.logs.len(), 2);
    
    // Check first entry
    let entry1 = &ima_log.logs[0];
    assert_eq!(entry1.pcr_index, 11);
    assert_eq!(entry1.template_hash, "65b3b8c28aba16023bb8d1eb774fbb3c0235cd8256ec193b4e9558f493f0c8f3");
    assert_eq!(entry1.file_path, "/usr/bin/kmod");
    
    // Check second entry
    let entry2 = &ima_log.logs[1];
    assert_eq!(entry2.pcr_index, 10);
    assert_eq!(entry2.template_hash, "d44df8df19bbb925d8a929bba30e2694bbd17abf9d14400c6fbfcd87c6d73065");
    assert_eq!(entry2.file_path, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
}
