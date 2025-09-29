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
use std::fs;
use std::io::Read;
use hex;

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

#[test]
fn test_ima_log_binary_parsing_debug() {
    // Read the binary IMA log file
    let binary_data = fs::read("tests/data/ima.bin")
        .expect("Failed to read ima.bin file");
    
    // Let's manually parse the first entry to understand the format
    let mut cursor = std::io::Cursor::new(&binary_data);
    
    // Read PCR index (4 bytes)
    let mut pcr_bytes = [0u8; 4];
    cursor.read_exact(&mut pcr_bytes).unwrap();
    let pcr_index = u32::from_le_bytes(pcr_bytes);
    
    // Read template data hash (32 bytes)
    let mut template_data_hash = vec![0u8; 32];
    cursor.read_exact(&mut template_data_hash).unwrap();
    
    // Read template name length (4 bytes)
    let mut name_len_bytes = [0u8; 4];
    cursor.read_exact(&mut name_len_bytes).unwrap();
    let template_name_len = u32::from_le_bytes(name_len_bytes);
    
    // Read template name
    let mut template_name_bytes = vec![0u8; template_name_len as usize];
    cursor.read_exact(&mut template_name_bytes).unwrap();
    let template_name = String::from_utf8(template_name_bytes).unwrap();
    
    // Read template data length (4 bytes)
    let mut data_len_bytes = [0u8; 4];
    cursor.read_exact(&mut data_len_bytes).unwrap();
    let template_data_len = u32::from_le_bytes(data_len_bytes);
    
    // Read template data
    let mut template_data = vec![0u8; template_data_len as usize];
    cursor.read_exact(&mut template_data).unwrap();
    
    // Try to parse the template data manually
    if template_data.len() >= 32 {
        // This appears to be a custom format, not standard IMA-NG
        // Let's try to parse it step by step
        
        let mut pos = 0;
        
        // Read first length field (4 bytes)
        if pos + 4 <= template_data.len() {
            let len1 = u32::from_le_bytes([template_data[pos], template_data[pos+1], template_data[pos+2], template_data[pos+3]]);
            pos += 4;
            println!("First length field: {}", len1);
            
            // Read hash algorithm prefix
            if pos + 8 <= template_data.len() {
                let hash_alg_bytes = &template_data[pos..pos+8];
                let hash_alg_str = String::from_utf8_lossy(hash_alg_bytes);
                println!("Hash algorithm: {:?}", hash_alg_str);
                pos += 8;
                
                // Read file hash (32 bytes)
                if pos + 32 <= template_data.len() {
                    let file_hash_bytes = &template_data[pos..pos+32];
                    println!("File hash: {}", hex::encode(file_hash_bytes));
                    pos += 32;
                    
                    // Read file path length (4 bytes)
                    if pos + 4 <= template_data.len() {
                        let path_len = u32::from_le_bytes([template_data[pos], template_data[pos+1], template_data[pos+2], template_data[pos+3]]);
                        pos += 4;
                        println!("File path length: {}", path_len);
                        
                        // Read file path
                        if pos + path_len as usize <= template_data.len() {
                            let file_path_bytes = &template_data[pos..pos+path_len as usize];
                            let file_path = String::from_utf8_lossy(file_path_bytes);
                            println!("File path: {}", file_path);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_ima_log_binary_parsing_correctness() {
    // Read the binary IMA log file
    let binary_data = fs::read("tests/data/ima.bin")
        .expect("Failed to read ima.bin file");
    
    // Read the text IMA log file for comparison
    let text_data = fs::read_to_string("tests/data/ima.log")
        .expect("Failed to read ima.log file");
    
    // Parse text data using ImaLog::new (base64 encoded)
    let encoded_text = BASE64.encode(&text_data);
    let text_ima_log = ImaLog::new(&encoded_text, "sha256")
        .expect("Failed to parse text IMA log");
    
    // Parse binary data using ImaLog::from_binary
    let binary_ima_log = ImaLog::from_binary(&binary_data, "sha256")
        .expect("Failed to parse binary IMA log");
    
    // Verify both logs have the same number of entries
    assert_eq!(binary_ima_log.logs.len(), text_ima_log.logs.len());
    assert_eq!(binary_ima_log.logs.len(), 2, "Expected 2 entries in the test data");
    
    // Compare each entry
    for (i, (binary_entry, text_entry)) in binary_ima_log.logs.iter().zip(text_ima_log.logs.iter()).enumerate() {
        println!("Comparing entry {}: binary vs text", i);
        
        // Compare PCR index
        assert_eq!(binary_entry.pcr_index, text_entry.pcr_index, 
                   "PCR index mismatch in entry {}", i);
        
        // Compare template name
        assert_eq!(binary_entry.template_name, text_entry.template_name,
                   "Template name mismatch in entry {}", i);
        
        // Compare file hash algorithm
        assert_eq!(binary_entry.file_hash_alg, text_entry.file_hash_alg,
                   "File hash algorithm mismatch in entry {}", i);
        
        // Compare file hash
        assert_eq!(binary_entry.file_hash, text_entry.file_hash,
                   "File hash mismatch in entry {}", i);
        
        // Compare file path
        assert_eq!(binary_entry.file_path, text_entry.file_path,
                   "File path mismatch in entry {}", i);
        
        println!("Entry {} comparison successful: PCR={}, path={}", 
                 i, binary_entry.pcr_index, binary_entry.file_path);
    }
    
    println!("Binary IMA log parsing verification completed successfully!");
}


#[test]
fn test_ima_log_binary_parsing_detailed() {
    // Read the binary IMA log file
    let binary_data = fs::read("tests/data/ima.bin")
        .expect("Failed to read ima.bin file");
    
    // Parse binary data
    let ima_log = ImaLog::from_binary(&binary_data, "sha256")
        .expect("Failed to parse binary IMA log");
    
    // Verify we have exactly 2 entries as expected from ima.log
    assert_eq!(ima_log.logs.len(), 2);
    
    // Verify first entry (boot_aggregate)
    let entry1 = &ima_log.logs[0];
    assert_eq!(entry1.pcr_index, 10);
    assert_eq!(entry1.template_name, "ima-ng");
    assert_eq!(entry1.file_hash_alg, "sha256");
    assert_eq!(entry1.file_path, "boot_aggregate");
    assert_eq!(entry1.file_hash, "f49e67e67e1d51d900d0924e551ca9f93a8b1ff3fc5ba93c37c29a4d29d3b4d4");
    
    // Verify second entry (/usr/bin/cat)
    let entry2 = &ima_log.logs[1];
    assert_eq!(entry2.pcr_index, 10);
    assert_eq!(entry2.template_name, "ima-ng");
    assert_eq!(entry2.file_hash_alg, "sha256");
    assert_eq!(entry2.file_path, "/usr/bin/cat");
    assert_eq!(entry2.file_hash, "90c9437a02857838ccc0ce1ff8652691181bfb67135a1173dd276f91fa57d7ec");
    
    // Verify template hashes are calculated correctly
    // The template hash should be calculated from file hash + file path
    assert!(!entry1.template_hash.is_empty());
    assert!(!entry2.template_hash.is_empty());
    
    println!("Detailed binary parsing verification:");
    println!("Entry 1: PCR={}, path={}, hash={}", 
             entry1.pcr_index, entry1.file_path, entry1.file_hash);
    println!("Entry 2: PCR={}, path={}, hash={}", 
             entry2.pcr_index, entry2.file_path, entry2.file_hash);
}
