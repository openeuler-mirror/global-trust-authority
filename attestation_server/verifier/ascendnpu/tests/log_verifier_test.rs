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
use ascend_npu_verifier::log_verifier::{LogResult, verify_all_logs};
use ascend_npu_verifier::verifier::AscendNpuPlugin;
use plugin_manager::ServiceHostFunctions;

// Mock ServiceHostFunctions for testing
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
    let results = verify_all_logs(&logs, &plugin, "test_user", None).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].verified);
    assert_eq!(results[0].log_type, "boot_measurement");
}

#[tokio::test]
async fn test_runtime_measurement_log_verification() {
    let logs = vec![
        Log {
            log_type: "runtime_measurement".to_string(),
            log_data: "dGVzdF9ydW50aW1lX2xvZw==".to_string(),
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let results = verify_all_logs(&logs, &plugin, "test_user", None).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].verified);
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
    let results = verify_all_logs(&logs, &plugin, "test_user", None).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].verified);
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
    let results = verify_all_logs(&logs, &plugin, "test_user", None).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].verified);
    assert_eq!(results[0].log_type, "boot_measurement");
}

#[tokio::test]
async fn test_multiple_logs_verification() {
    let logs = vec![
        Log {
            log_type: "boot_measurement".to_string(),
            log_data: "dGVzdF9ib290X2xvZw==".to_string(),
        },
        Log {
            log_type: "runtime_measurement".to_string(),
            log_data: "dGVzdF9ydW50aW1lX2xvZw==".to_string(),
        },
        Log {
            log_type: "unsupported_log".to_string(),
            log_data: "dGVzdF9sb2c=".to_string(),
        }
    ];

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let results = verify_all_logs(&logs, &plugin, "test_user", None).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 3);
    
    // Check that boot_measurement and runtime_measurement are verified
    let boot_result = results.iter().find(|r| r.log_type == "boot_measurement").unwrap();
    assert!(boot_result.verified);
    
    let runtime_result = results.iter().find(|r| r.log_type == "runtime_measurement").unwrap();
    assert!(runtime_result.verified);
    
    // Check that unsupported log is not verified
    let unsupported_result = results.iter().find(|r| r.log_type == "unsupported_log").unwrap();
    assert!(!unsupported_result.verified);
}

#[tokio::test]
async fn test_log_result_creation() {
    let success_result = LogResult::success("test_log".to_string(), "Success message".to_string());
    assert!(success_result.verified);
    assert_eq!(success_result.log_type, "test_log");
    assert_eq!(success_result.message, "Success message");
    
    let failure_result = LogResult::failure("test_log".to_string(), "Failure message".to_string());
    assert!(!failure_result.verified);
    assert_eq!(failure_result.log_type, "test_log");
    assert_eq!(failure_result.message, "Failure message");
}

#[tokio::test]
async fn test_empty_log_list_verification() {
    let logs = vec![]; // Empty log list

    let plugin = AscendNpuPlugin::new("test_config".to_string(), create_mock_host_functions());
    let results = verify_all_logs(&logs, &plugin, "test_user", None).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 0); // No logs to verify
}

#[tokio::test]
async fn test_log_result_json_conversion() {
    let result = LogResult::success("test_log".to_string(), "Test message".to_string());
    let json_value = result.to_json_value();
    
    assert_eq!(json_value["log_type"], "test_log");
    assert_eq!(json_value["verified"], true);
    assert_eq!(json_value["message"], "Test message");
}
