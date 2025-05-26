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

use tpm_dim_verifier::dim_log::{DimLog, DimLogEntry, HashAlgorithm};
use tpm_common_verifier::PcrValues;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[test]
fn test_parse_valid_log_line() {
    let line = "12 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969 sha256:3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969 /boot/vmlinuz [kernel]";
    let parsed = DimLog::parse_log_line(line).unwrap();
    assert_eq!(parsed.pcr_index, 12);
    assert_eq!(parsed.log_entry.file_path, "/boot/vmlinuz");
    assert_eq!(parsed.log_entry.log_type, "kernel");
    assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256);
}

#[test]
fn test_parse_invalid_log_line() {
    let line = "12 0123456789abcdef sha256:abcdef /boot/vmlinuz [kernel]";
    let result = DimLog::parse_log_line(line);
    assert!(result.is_err());
}

#[test]
fn test_parse_log_with_invalid_pcr_index() {
    let line = "24 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef /boot/vmlinuz [kernel]";
    let result = DimLog::parse_log_line(line);
    assert!(result.is_err());
}

#[test]
fn test_parse_log_with_invalid_hash_algorithm() {
    let line = "12 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef invalid:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef /boot/vmlinuz [kernel]";
    let result = DimLog::parse_log_line(line);
    assert!(result.is_err());
}

#[test]
fn test_parse_static_baseline_log() {
    let line = "0 e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e sha256:02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989 /opt/dim/demo/dim_test_demo [static_baseline]";
    let parsed = DimLog::parse_log_line(line).unwrap();
    assert_eq!(parsed.pcr_index, 0);
    assert_eq!(parsed.log_entry.file_path, "/opt/dim/demo/dim_test_demo");
    assert_eq!(parsed.log_entry.log_type, "static_baseline");
    assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256);
    assert_eq!(parsed.log_entry.template_hash, "e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e");
    assert_eq!(parsed.log_entry.file_hash, "02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989");
}

#[test]
fn test_parse_tampered_log() {
    let line = "0 08a2f6f2922ad3d1cf376ae05cf0cc507c2f5a1c605adf445506bc84826531d6 sha256:855ec9a890ff22034f7e13b78c2089e28e8d217491665b39203b50ab47b111c8 /opt/dim/demo/dim_test_demo [tampered]";
    let parsed = DimLog::parse_log_line(line).unwrap();
    assert_eq!(parsed.pcr_index, 0);
    assert_eq!(parsed.log_entry.file_path, "/opt/dim/demo/dim_test_demo");
    assert_eq!(parsed.log_entry.log_type, "tampered");
    assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256);
    assert_eq!(parsed.log_entry.template_hash, "08a2f6f2922ad3d1cf376ae05cf0cc507c2f5a1c605adf445506bc84826531d6");
    assert_eq!(parsed.log_entry.file_hash, "855ec9a890ff22034f7e13b78c2089e28e8d217491665b39203b50ab47b111c8");
}

#[test]
fn test_create_dim_log_with_mixed_states() {
    let log_content = "0 e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e sha256:02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989 /opt/dim/demo/dim_test_demo [static_baseline]\n\
0 08a2f6f2922ad3d1cf376ae05cf0cc507c2f5a1c605adf445506bc84826531d6 sha256:855ec9a890ff22034f7e13b78c2089e28e8d217491665b39203b50ab47b111c8 /opt/dim/demo/dim_test_demo [tampered]";
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    assert!(!dim_log.logs.is_empty());
    assert!(dim_log.logs.contains_key(&0));
    
    let entries = dim_log.logs.get(&0).unwrap();
    assert_eq!(entries.len(), 2);
    
    // 验证 static baseline 条目
    let baseline_entry = entries.iter().find(|e| e.log_type == "static_baseline").unwrap();
    assert_eq!(baseline_entry.file_path, "/opt/dim/demo/dim_test_demo");
    assert_eq!(baseline_entry.template_hash, "e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e");
    assert_eq!(baseline_entry.file_hash, "02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989");
    
    // 验证 tampered 条目
    let tampered_entry = entries.iter().find(|e| e.log_type == "tampered").unwrap();
    assert_eq!(tampered_entry.file_path, "/opt/dim/demo/dim_test_demo");
    assert_eq!(tampered_entry.template_hash, "08a2f6f2922ad3d1cf376ae05cf0cc507c2f5a1c605adf445506bc84826531d6");
    assert_eq!(tampered_entry.file_hash, "855ec9a890ff22034f7e13b78c2089e28e8d217491665b39203b50ab47b111c8");
}

#[test]
fn test_create_dim_log_from_base64() {
    let log_content = "0 e9a79e25f091e03a8b3972b1a0e4ae2ccaed1f5652857fe3b4dc947801a6913e sha256:02e28dff9997e1d81fb806ee5b784fd853eac8812059c4dba7c119c5e5076989 /opt/dim/demo/dim_test_demo [static_baseline]";
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    assert!(!dim_log.logs.is_empty());
    assert!(dim_log.logs.contains_key(&0));
    
    let entries = dim_log.logs.get(&0).unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.file_path, "/opt/dim/demo/dim_test_demo");
    assert_eq!(entry.log_type, "static_baseline");
}

#[test]
fn test_create_dim_log_from_relative_path() {
    let log_content = "0 9603a9d5f87851c8eb7d2619f7abbe28cb8a91f9c83f5ea59f036794e23d1558 sha256:9da4bccc7ae1b709deab8f583b244822d52f3552c93f70534932ae21fac931c6 dim_test_module [static_baseline]";
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    assert!(!dim_log.logs.is_empty());
    assert!(dim_log.logs.contains_key(&0));
    
    let entries = dim_log.logs.get(&0).unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.file_path, "dim_test_module");
    assert_eq!(entry.log_type, "static_baseline");
}

#[test]
fn test_collect_file_hashes() {
    let mut logs = HashMap::new();
    let entry = DimLogEntry {
        pcr_index: 12,
        template_hash: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969".to_string(),
        file_hash_alg: HashAlgorithm::Sha256,
        file_hash: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969".to_string(),
        file_path: "/boot/vmlinuz".to_string(),
        log_type: "kernel".to_string(),
        ref_value_matched: None,
    };
    logs.insert(12, vec![entry]);
    let dim_log = DimLog { logs };
    let hashes = dim_log.collect_file_hashes().unwrap();
    assert_eq!(hashes.len(), 1);
}

#[test]
fn test_collect_file_hashes_with_duplicate_path() {
    let mut logs = HashMap::new();
    let entry = DimLogEntry {
        pcr_index: 12,
        template_hash: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969".to_string(),
        file_hash_alg: HashAlgorithm::Sha256,
        file_hash: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969".to_string(),
        file_path: "/boot/vmlinuz".to_string(),
        log_type: "kernel".to_string(),
        ref_value_matched: None,
    };
    logs.insert(12, vec![entry.clone(), entry]);
    let dim_log = DimLog { logs };
    let result = dim_log.collect_file_hashes();
    assert!(result.is_err());
}

#[test]
fn test_to_json_value() {
    let mut logs = HashMap::new();
    let entry = DimLogEntry {
        pcr_index: 12,
        template_hash: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969".to_string(),
        file_hash_alg: HashAlgorithm::Sha256,
        file_hash: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969".to_string(),
        file_path: "/boot/vmlinuz".to_string(),
        log_type: "kernel".to_string(),
        ref_value_matched: None,
    };
    logs.insert(12, vec![entry]);
    let dim_log = DimLog { logs };
    let json = dim_log.to_json_value().unwrap();
    assert!(json.is_object());
}

#[test]
fn test_parse_log_with_empty_line() {
    let line = "";
    let result = DimLog::parse_log_line(line);
    assert!(result.is_err());
}

#[test]
fn test_parse_log_with_whitespace_only() {
    let line = "   ";
    let result = DimLog::parse_log_line(line);
    assert!(result.is_err());
}

#[test]
fn test_create_dim_log_with_empty_data() {
    let log_data = BASE64.encode("");
    let result = DimLog::new(&log_data);
    assert!(result.is_err());
}

#[test]
fn test_create_dim_log_with_invalid_base64() {
    let log_data = "invalid base64 data";
    let result = DimLog::new(log_data);
    assert!(result.is_err());
}

#[test]
fn test_parse_dynamic_baseline_log() {
    let line = "0 c1b0d9909ddb00633fc6bbe7e457b46b57e165166b8422e81014bdd3e6862899 sha256:35494ed41109ebc9bf9bf7b1c190b7e890e2f7ce62ca1920397cd2c02a057796 dim_core.text [dynamic_baseline]";
    let parsed = DimLog::parse_log_line(line).unwrap();
    assert_eq!(parsed.pcr_index, 0);
    assert_eq!(parsed.log_entry.file_path, "dim_core.text");
    assert_eq!(parsed.log_entry.log_type, "dynamic_baseline");
    assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256);
    assert_eq!(parsed.log_entry.template_hash, "c1b0d9909ddb00633fc6bbe7e457b46b57e165166b8422e81014bdd3e6862899");
    assert_eq!(parsed.log_entry.file_hash, "35494ed41109ebc9bf9bf7b1c190b7e890e2f7ce62ca1920397cd2c02a057796");
}

#[test]
fn test_parse_no_static_baseline_log() {
    let line = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e ext4 [no_static_baseline]";
    let parsed = DimLog::parse_log_line(line).unwrap();
    assert_eq!(parsed.pcr_index, 0);
    assert_eq!(parsed.log_entry.file_path, "ext4");
    assert_eq!(parsed.log_entry.log_type, "no_static_baseline");
    assert_eq!(parsed.log_entry.file_hash_alg, HashAlgorithm::Sha256);
    assert_eq!(parsed.log_entry.template_hash, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    assert_eq!(parsed.log_entry.file_hash, "db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e");
}

#[test]
fn test_dim_log_new_and_to_json() {
    // 正常情况
    let log_content = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e ext4 [static_baseline]";
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    assert!(dim_log.logs.contains_key(&0));
    let json = dim_log.to_json_value().unwrap();
    assert!(json.is_object());

    // 异常情况：无效 base64
    let result = DimLog::new("!!!invalid base64!!!");
    assert!(result.is_err());
}

#[test]
fn test_replay_pcr_values_success() {
    // 构造合法的 log_content
    let template_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let file_hash = "5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02";
    let log_content = format!(
        "0 {} sha256:{} test_file [static baseline]",
        template_hash, file_hash
    );
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    let mut pcr_values = PcrValues::new();
    pcr_values.hash_alg = "sha256".to_string();
    let initial_value = PcrValues::create_initial_pcr_value("sha256", 0, None).unwrap();
    pcr_values.set_pcr_value(0, initial_value);
    let result = dim_log.replay_pcr_values(&mut pcr_values);
    assert!(result.is_ok());
}

#[test]
fn test_replay_pcr_values_template_hash_mismatch() {
    // 构造 log entry
    let entry = DimLogEntry {
        pcr_index: 0,
        template_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        file_hash_alg: HashAlgorithm::Sha256,
        file_hash: "db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e".to_string(),
        file_path: "ext4".to_string(),
        log_type: "static_baseline".to_string(),
        ref_value_matched: None,
    };
    let log_content = format!(
        "0 {} sha256:{} ext4 [static_baseline]",
        entry.template_hash, entry.file_hash
    );
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    let mut pcr_values = PcrValues::new();
    // 初始值与模板 hash 不匹配
    pcr_values.set_pcr_value(0, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
    let result = dim_log.replay_pcr_values(&mut pcr_values);
    assert!(result.is_err());
}

#[test]
fn test_replay_pcr_values_multiple_entries() {
    let template_hash1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let template_hash2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let file_hash1 = "5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02";
    let file_hash2 = "b279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa03";
    let log_content = format!(
        "2 {} sha256:{} test_file1 [static baseline]\n2 {} sha256:{} test_file2 [static baseline]",
        template_hash1, file_hash1, template_hash2, file_hash2
    );
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    let mut pcr_values = PcrValues::new();
    pcr_values.hash_alg = "sha256".to_string();
    let initial_value = PcrValues::create_initial_pcr_value("sha256", 2, None).unwrap();
    pcr_values.set_pcr_value(2, initial_value);
    let result = dim_log.replay_pcr_values(&mut pcr_values);
    assert!(result.is_ok());
}

#[test]
fn test_replay_pcr_values_empty_log() {
    let log_data = BASE64.encode("");
    let result = DimLog::new(&log_data);
    assert!(result.is_err()); // 空日志应返回错误
}

#[test]
fn test_replay_pcr_values_pcr_index_not_exist() {
    let template_hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let file_hash = "5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02";
    let log_content = format!(
        "5 {} sha256:{} test_file2 [static baseline]",
        template_hash, file_hash
    );
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    let mut pcr_values = PcrValues::new();
    pcr_values.hash_alg = "sha256".to_string();
    let initial_value = PcrValues::create_initial_pcr_value("sha256", 5, None).unwrap();
    pcr_values.set_pcr_value(5, initial_value);
    let result = dim_log.replay_pcr_values(&mut pcr_values);
    assert!(result.is_ok());
}

#[test]
fn test_dim_log_collect_file_hashes() {
    let log_content = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e ext4 [static_baseline]\n\
                      1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:db032449f9e20ba37e0ec4a506d664f24f496bce95f2ed972419397951a3792e ext4 [static_baseline]";
    let log_data = BASE64.encode(log_content);
    let dim_log = DimLog::new(&log_data).unwrap();
    let result = dim_log.collect_file_hashes();
    assert!(result.is_err()); // 应该失败，因为有重复的文件路径
}

#[test]
fn test_replay_pcr_values_empty_log_pcr_not_initial() {
    // 构造空日志
    let log_data = BASE64.encode("");
    let result = DimLog::new(&log_data);
    assert!(result.is_err()); // 空日志本身就会报错

    // 直接构造 DimLog { logs: HashMap::new() } 进行 replay_pcr_values 测试
    let dim_log = DimLog { logs: std::collections::HashMap::new() };
    let mut pcr_values = PcrValues::new();
    // 设置 pcr_index 0 为非初始值
    pcr_values.set_pcr_value(0, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
    let result = dim_log.replay_pcr_values(&mut pcr_values);
    assert!(result.is_err());
}
