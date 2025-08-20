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

use std::collections::HashMap;

use plugin_manager::{PluginError, ServiceHostFunctions};
use serde_json::json;

use virtcca_verifier::constants::CVM_REM_ARR_SIZE;
use virtcca_verifier::evidence::Log;
use virtcca_verifier::log_verifier::{ImaVerify, LogResult, UefiVerify, verify_all_logs};
use virtcca_verifier::verifier::VirtCCAPlugin;

fn create_default_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    }
}

// Helper function to create a dummy cvm_token_rem
fn create_dummy_cvm_token_rem() -> [Vec<u8>; CVM_REM_ARR_SIZE] {
    let mut arr: [Vec<u8>; CVM_REM_ARR_SIZE] = std::array::from_fn(|_| Vec::new());
    for i in 0..CVM_REM_ARR_SIZE {
        arr[i] = vec![0u8; 32]; // 32-byte dummy hash
    }
    arr
}

#[tokio::test]
async fn test_uefi_log_verify_invalid_base64() {
    let uefi_log = "invalid_base64_string";
    let cvm_token_rem = create_dummy_cvm_token_rem();
    let log_result = LogResult::new("CCEL".to_string());

    let result = UefiVerify::uefi_log_verify(uefi_log, cvm_token_rem, log_result);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("Failed to decode base64 log"));
    } else {
        panic!("Expected InputError for invalid base64");
    }
}

#[tokio::test]
async fn test_ima_log_verify_invalid_ima_log() {
    let ima_log = "invalid_ima_log_format";
    let cvm_token_rem = create_dummy_cvm_token_rem();
    let log_result = LogResult::new("ImaLog".to_string());
    let host_functions = create_default_host_functions();
    let plugin = VirtCCAPlugin::new("virt_cca".to_string(), host_functions);
    let user_id = "test_user";

    let result = ImaVerify::ima_log_verify(ima_log, cvm_token_rem, log_result, &plugin, user_id).await;
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("Failed to parse IMA log"));
    } else {
        panic!("Expected InputError for invalid IMA log");
    }
}

#[tokio::test]
async fn test_verify_all_logs_empty_logs() {
    let logs: Option<Vec<Log>> = None;
    let cvm_token_rem = create_dummy_cvm_token_rem();
    let host_functions = create_default_host_functions();
    let plugin = VirtCCAPlugin::new("virt_cca".to_string(), host_functions);
    let user_id = "test_user";

    let result = verify_all_logs(logs.as_ref(), cvm_token_rem, &plugin, user_id).await;
    assert!(result.is_ok());
    let log_results = result.unwrap();
    assert_eq!(log_results.len(), 2);
    assert!(log_results.iter().any(|lr| lr.log_type == "CCEL"));
    assert!(log_results.iter().any(|lr| lr.log_type == "ImaLog"));
}

#[tokio::test]
async fn test_verify_all_logs_invalid_log_type() {
    let logs = Some(vec![
        Log {
            log_type: "InvalidLog".to_string(),
            log_data: "some_data".to_string(),
        },
    ]);
    let cvm_token_rem = create_dummy_cvm_token_rem();
    let host_functions = create_default_host_functions();
    let plugin = VirtCCAPlugin::new("virt_cca".to_string(), host_functions);
    let user_id = "test_user";

    let result = verify_all_logs(logs.as_ref(), cvm_token_rem, &plugin, user_id).await;
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("Invalid log type"));
    } else {
        panic!("Expected InputError for invalid log type");
    }
}

#[tokio::test]
async fn test_verify_all_logs_too_many_logs() {
    let logs = Some(vec![
        Log { log_type: "CCEL".to_string(), log_data: "data1".to_string() },
        Log { log_type: "ImaLog".to_string(), log_data: "data2".to_string() },
        Log { log_type: "CCEL".to_string(), log_data: "data3".to_string() },
    ]);
    let cvm_token_rem = create_dummy_cvm_token_rem();
    let host_functions = create_default_host_functions();
    let plugin = VirtCCAPlugin::new("virt_cca".to_string(), host_functions);
    let user_id = "test_user";

    let result = verify_all_logs(logs.as_ref(), cvm_token_rem, &plugin, user_id).await;
    assert!(result.is_err());
    if let Err(PluginError::InternalError(msg)) = result {
        assert!(msg.contains("logs length should not exceed 2"));
    } else {
        panic!("Expected InternalError for too many logs");
    }
}

#[test]
fn test_log_result_to_json_value() {
    let log_result_ima = LogResult {
        log_status: "replay_success".to_string(),
        ref_value_match_status: "matched".to_string(),
        log_type: "ImaLog".to_string(),
        log_data: Some(json!({ "key": "value" })),
    };
    let json_ima = log_result_ima.to_json_value();
    assert_eq!(json_ima["vcca_ima_log_status"], "replay_success");
    assert_eq!(json_ima["vcca_ima_ref_value_match_status"], "matched");
    assert_eq!(json_ima["vcca_ima_log_type"], "ImaLog");
    assert_eq!(json_ima["vcca_ima_log_data"], json!({ "key": "value" }));

    let log_result_ccel = LogResult {
        log_status: "replay_failure".to_string(),
        ref_value_match_status: "unmatched".to_string(),
        log_type: "CCEL".to_string(),
        log_data: None,
    };
    let json_ccel = log_result_ccel.to_json_value();
    assert_eq!(json_ccel["vcca_ccel_log_status"], "replay_failure");
    assert_eq!(json_ccel["vcca_ccel_ref_value_match_status"], "unmatched");
    assert_eq!(json_ccel["vcca_ccel_log_type"], "CCEL");
    assert!(json_ccel.get("vcca_ccel_log_data").is_none());

    let log_result_other = LogResult {
        log_status: "unknown".to_string(),
        ref_value_match_status: "ignore".to_string(),
        log_type: "OtherLog".to_string(),
        log_data: None,
    };
    let json_other = log_result_other.to_json_value();
    assert_eq!(json_other["log_status"], "unknown");
    assert_eq!(json_other["ref_value_match_status"], "ignore");
    assert_eq!(json_other["log_type"], "OtherLog");
}

#[test]
fn test_log_result_new() {
    let log_result = LogResult::new("TestLog".to_string());
    assert_eq!(log_result.log_status, "no_log");
    assert_eq!(log_result.ref_value_match_status, "ignore");
    assert_eq!(log_result.log_type, "TestLog");
    assert!(log_result.log_data.is_none());
}

#[test]
fn test_compare_rtmr_with_uefi_log() {
    let mut replayed_rtmr = HashMap::new();
    let mut uefi_log_hash: [Vec<u8>; CVM_REM_ARR_SIZE] = std::array::from_fn(|_| Vec::new());

    for i in 0..CVM_REM_ARR_SIZE {
        let data = vec![i as u8; 32];
        replayed_rtmr.insert((i + 1) as u32, data.clone());
        uefi_log_hash[i] = data;
    }
    assert!(UefiVerify::compare_rtmr_with_uefi_log(&replayed_rtmr, &uefi_log_hash));

    let mut replayed_rtmr_missing = replayed_rtmr.clone();
    replayed_rtmr_missing.remove(&1);
    assert!(!UefiVerify::compare_rtmr_with_uefi_log(&replayed_rtmr_missing, &uefi_log_hash));

    let mut replayed_rtmr_len_mismatch = replayed_rtmr.clone();
    replayed_rtmr_len_mismatch.insert(1, vec![0u8; 30]);
    assert!(!UefiVerify::compare_rtmr_with_uefi_log(&replayed_rtmr_len_mismatch, &uefi_log_hash));
}
