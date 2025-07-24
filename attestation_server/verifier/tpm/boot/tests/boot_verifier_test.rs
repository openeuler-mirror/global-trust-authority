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

use std::fs::File;
use std::io::Write;
use serde_json::Value;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use plugin_manager::{ServicePlugin, ServiceHostFunctions, PluginError};
use tpm_boot_verifier::TpmBootPlugin;

mod utils;
use utils::{read_file_as_base64, corrupt_base64_data};

// Helper function to create a default service host functions
fn create_default_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    }
}

// Helper function to create host functions with certificate validation result
fn create_host_functions_with_cert_validation(validation_result: bool) -> ServiceHostFunctions {
    ServiceHostFunctions {
        validate_cert_chain: Box::new(move |_, _, _| Box::pin(async move { validation_result })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    }
}
// Helper function to update log data in evidence
fn update_log_data(evidence_json: &mut Value, log_data: &str) -> Result<(), String> {
    if let Some(logs) = evidence_json["evidence"]["logs"].as_array_mut() {
        if let Some(log) = logs.get_mut(0) {
            log["log_type"] = serde_json::Value::String("TcgEventLog".to_string());
            log["log_data"] = serde_json::Value::String(log_data.to_string());
            return Ok(());
        }
    }
    Err("Failed to update log data in evidence".to_string())
}

// Helper function to remove a field from evidence
fn remove_field(evidence_json: &mut Value, field_path: &[&str]) -> Result<(), String> {
    let mut current = evidence_json;

    // Navigate to parent object
    for &field in field_path.iter().take(field_path.len() - 1) {
        current = current.get_mut(field)
            .ok_or_else(|| format!("Field {} not found", field))?;
    }

    // Remove the last field
    let last_field = field_path.last().unwrap();
    if current.as_object_mut().map(|obj| obj.remove(*last_field)).is_none() {
        return Err(format!("Failed to remove field {}", last_field));
    }

    Ok(())
}

#[tokio::test]
async fn test_tpm_boot_plugin_with_valid_evidence() {
    let evidence_path = "tests/data/test_evidence.json";
    let evidence = std::fs::read_to_string(evidence_path)
        .expect("Failed to read test evidence file");
    let mut evidence_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");

    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    if let Some(logs) = evidence_json["evidence"]["logs"].as_array_mut() {
        if let Some(log) = logs.get_mut(0) {
            log["log_type"] = serde_json::Value::String("TcgEventLog".to_string());
            log["log_data"] = serde_json::Value::String(base64_content);
        }
    }

    let nonce = "ljYr8vYNYrErFHGKeiL4vg==";
    let nonce_decoded = BASE64.decode(nonce).unwrap();
    
    let service_host_functions = create_default_host_functions();

    let plugin = TpmBootPlugin::new("tpm_boot".to_string(), service_host_functions);

    let evidence_data = &evidence_json["evidence"];
    let result = plugin.verify_evidence("user_id", None, &evidence_data, Some(&nonce_decoded)).await;
    assert!(result.is_ok(), "Verification should have succeeded, but failed: {:?}", result.err());

   // Check result details
   let verification_result = result.as_ref().unwrap();
   assert!(verification_result["evidence"].is_object(), "Result should contain evidence object");
   assert!(verification_result["evidence"]["logs"].is_array(), "Result should contain logs array");
   assert!(verification_result["evidence"]["pcrs"].is_object(), "Result should contain pcrs object");

   // Check PCR verification results
   let pcr_values = &verification_result["evidence"]["pcrs"]["pcr_values"];
   assert!(pcr_values.is_array(), "PCR values should be an array");

    let result_path = "tests/data/result.json";
    let mut result_file = File::create(result_path).unwrap();

    match &result {
        Ok(value) => {
            let json_str = serde_json::to_string_pretty(value).unwrap();
            result_file.write_all(json_str.as_bytes()).unwrap();
        },
        Err(e) => {
            result_file.write_all(format!("Error: {}", e).as_bytes()).unwrap();
        }
    };

}

#[test]
fn test_tpm_boot_plugin_sample_output_vaild() {
    let service_host_functions = create_default_host_functions();
    let plugin = TpmBootPlugin::new("tpm_boot".to_string(), service_host_functions);
    let sample_output = plugin.get_sample_output();

    let event = &sample_output["evidence"]["logs"][0]["log_data"][0]["event"];
    let secure_boot = event["variable_data"]["SecureBoot"]["enabled"].as_str();
    assert!(secure_boot.is_some());
    assert_eq!(secure_boot.unwrap(), "No");
}

/// Missing Evidence Test
/// Objective: Verify the ability to handle missing evidence
/// Test data: Incomplete evidence missing Quote/logs/PCR values/certificates
/// Expected result: Returns InvalidEvidence error, indicating the missing component
#[tokio::test]
async fn test_missing_evidence_components() {
    let evidence_path = "tests/data/test_evidence.json";

    // Read test data
    let evidence = std::fs::read_to_string(evidence_path)
        .expect("Failed to read test evidence file");

    // Test missing Quote
    let mut missing_quote_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");
    remove_field(&mut missing_quote_json, &["evidence", "quote"])
        .expect("Failed to remove quote field");

    // Test missing PCR values
    let mut missing_pcrs_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");
    remove_field(&mut missing_pcrs_json, &["evidence", "pcrs"])
        .expect("Failed to remove pcrs field");

    // Test missing logs
    let mut missing_logs_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");
    remove_field(&mut missing_logs_json, &["evidence", "logs"])
        .expect("Failed to remove logs field");

    // Test missing certificate
    let mut missing_cert_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");
    remove_field(&mut missing_cert_json, &["evidence", "ak_cert"])
        .expect("Failed to remove ak_cert field");

    // Set nonce
    let nonce = "ljYr8vYNYrErFHGKeiL4vg==";
    let nonce_decoded = BASE64.decode(nonce).unwrap();

    // Configure host service functions
    let service_host_functions = create_default_host_functions();

    // Create plugin
    let plugin = TpmBootPlugin::new("tpm_boot".to_string(), service_host_functions);

    // Test missing Quote
    let result_missing_quote = plugin.verify_evidence(
        "user_id", None, &missing_quote_json["evidence"], Some(&nonce_decoded)
    ).await;
    assert!(result_missing_quote.is_err(), "Missing Quote should cause an error");
    assert!(matches!(result_missing_quote.err().unwrap(), PluginError::InputError(_)));

    // Test missing PCR values
    let result_missing_pcrs = plugin.verify_evidence(
        "user_id", None, &missing_pcrs_json["evidence"], Some(&nonce_decoded)
    ).await;
    assert!(result_missing_pcrs.is_err(), "Missing PCR values should cause an error");
    assert!(matches!(result_missing_pcrs.err().unwrap(), PluginError::InputError(_)));

    // Test missing logs
    let result_missing_logs = plugin.verify_evidence(
        "user_id", None, &missing_logs_json["evidence"], Some(&nonce_decoded)
    ).await;
    assert!(result_missing_logs.is_ok(), "Missing logs should not be an error");

    // Test missing certificate
    let result_missing_cert = plugin.verify_evidence(
        "user_id", None, &missing_cert_json["evidence"], Some(&nonce_decoded)
    ).await;
    assert!(result_missing_cert.is_err(), "Missing certificate should cause an error");
    assert!(matches!(result_missing_cert.err().unwrap(), PluginError::InputError(_)));
}

/// Certificate Validation Failure Test
/// Objective: Verify the ability to handle invalid certificates
/// Test data: Invalid or expired AK certificate
/// Expected result: Returns CertificateError error
#[tokio::test]
async fn test_certificate_validation_failure() {
    let evidence_path = "tests/data/test_evidence.json";

    // Read test data
    let evidence = std::fs::read_to_string(evidence_path)
        .expect("Failed to read test evidence file");
    let evidence_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");

    // Set nonce
    let nonce = "ljYr8vYNYrErFHGKeiL4vg==";
    let nonce_decoded = BASE64.decode(nonce).unwrap();

    // Configure host service functions, certificate validation fails
    let service_host_functions = create_host_functions_with_cert_validation(false);

    // Create plugin and verify
    let plugin = TpmBootPlugin::new("tpm_boot".to_string(), service_host_functions);
    let evidence_data = &evidence_json["evidence"];
    let result = plugin.verify_evidence("user_id", None, &evidence_data, Some(&nonce_decoded)).await;

    // Verify result
    assert!(result.is_err(), "Certificate validation failure should cause an error");

    // Check error type
    match result.err().unwrap() {
        PluginError::InputError(_) => {
            // Correct error type
        },
        err => {
            panic!("Expected certificate error, but got a different error: {:?}", err);
        }
    }
}

/// Internal Error Recovery Test
/// Objective: Verify the ability to recover from internal errors
/// Test data: Special input causing internal exceptions
/// Expected result: Returns InternalError error, does not crash
#[tokio::test]
async fn test_internal_error_recovery() {
    let evidence_path = "tests/data/test_evidence.json";

    // Read test data
    let evidence = std::fs::read_to_string(evidence_path)
        .expect("Failed to read test evidence file");
    let mut evidence_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");

    // Create corrupted log data
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Deliberately corrupt data
    let corrupted_content = corrupt_base64_data(&base64_content);
    update_log_data(&mut evidence_json, &corrupted_content)
        .expect("Failed to update log data with corrupted content");

    // Set invalid PCR value, not a valid hex string
    if let Some(pcrs) = evidence_json["evidence"]["pcrs"]["pcr_values"].as_array_mut() {
        if let Some(pcr0) = pcrs.get_mut(0) {
            pcr0["pcr_value"] = serde_json::Value::String("not_a_valid_hex_string".to_string());
        }
    }

    // Set nonce
    let nonce = "ljYr8vYNYrErFHGKeiL4vg==";
    let nonce_decoded = BASE64.decode(nonce).unwrap();

    // Configure host service functions
    let service_host_functions = create_default_host_functions();

    // Create plugin and verify
    let plugin = TpmBootPlugin::new("tpm_boot".to_string(), service_host_functions);
    let evidence_data = &evidence_json["evidence"];

    // Verification should return an error rather than crashing
    let result = plugin.verify_evidence("user_id", None, &evidence_data, Some(&nonce_decoded)).await;

    // Verify result
    assert!(result.is_err(), "Corrupted data should cause an error");

    // Test should reach here, not crash
    println!("Test completed successfully, error: {:?}", result.err());
}
