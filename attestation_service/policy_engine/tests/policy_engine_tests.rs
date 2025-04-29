use std::fs;
use std::path::PathBuf;
use serde_json::Value;

use policy_engine::{evaluate_policy, PolicyEvaluationError};
use std::thread;
use std::sync::Arc;

fn read_test_policy(filename: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/data/policies");
    path.push(filename);
    fs::read_to_string(path).expect("Failed to read policy file")
}

fn read_test_input(filename: &str) -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/data/inputs");
    path.push(filename);
    let content = fs::read_to_string(path).expect("Failed to read input file");
    serde_json::from_str(&content).expect("Failed to parse input JSON")
}

#[test]
fn test_evaluate_policy_success() {
    let input = read_test_input("test_input.json");
    let policy = read_test_policy("valid_policy.rego");
    
    let result = evaluate_policy(&input, &policy).unwrap();
    
    // Verify attestation_valid is true
    let attestation_valid = result["attestation_valid"].as_bool().expect("Missing attestation_valid");
    assert!(attestation_valid, "Expected attestation_valid to be true");

    // Verify custom_data contains matching_pcrs
    let matching_pcrs = result["custom_data"]["matching_pcrs"]
        .as_array()
        .expect("Missing matching_pcrs array");
    assert_eq!(matching_pcrs.len(), 5, "Expected 5 matching PCRs");
}

#[test]
fn test_evaluate_policy_pcr_mismatch() {
    let input = read_test_input("test_input_pcr_not_match.json");
    let policy = read_test_policy("valid_policy.rego");
    
    let result = evaluate_policy(&input, &policy).unwrap();
    
    // Verify attestation_valid is false
    let attestation_valid = result["attestation_valid"].as_bool().expect("Missing attestation_valid");
    assert!(!attestation_valid, "Expected attestation_valid to be false");

    // Verify custom_data contains matching_pcrs
    let matching_pcrs = result["custom_data"]["matching_pcrs"]
        .as_array()
        .expect("Missing matching_pcrs array");
    assert_eq!(matching_pcrs.len(), 3, "Expected 3 matching PCRs");
}

#[test]
fn test_evaluate_policy_compilation_error() {
    let input = read_test_input("test_input.json");
    let policy = read_test_policy("not_compilable_policy.rego");
    
    match evaluate_policy(&input, &policy) {
        Err(PolicyEvaluationError::CompileError(_)) => (),
        other => panic!("Expected CompileError, got: {:?}", other),
    }
}

#[test]
fn test_evaluate_policy_size_limit() {
    let input = read_test_input("test_input.json");
    let policy = read_test_policy("large_output_policy.rego");
    
    match evaluate_policy(&input, &policy) {
        Err(PolicyEvaluationError::OutputSizeLimitError(_, _)) => (),
        other => panic!("Expected OutputSizeLimitError, got: {:?}", other),
    }
}

#[test]
fn test_evaluate_policy_thread_safety() {
    let input = read_test_input("test_input.json");
    let policy = read_test_policy("valid_policy.rego");
    
    // Create shared input and policy
    let input = Arc::new(input);
    let policy = Arc::new(policy);

    // Spawn multiple threads to evaluate policy concurrently
    let mut handles = vec![];
    for _ in 0..10 {
        let input = Arc::clone(&input);
        let policy = Arc::clone(&policy);
        
        let handle = thread::spawn(move || {
            let result = evaluate_policy(&input, &policy).unwrap();
            
            // Verify attestation_valid is true
            let attestation_valid = result["attestation_valid"].as_bool().expect("Missing attestation_valid");
            assert!(attestation_valid);
            
            // Verify custom_data contains matching_pcrs
            let matching_pcrs = result["custom_data"]["matching_pcrs"].as_array().expect("Missing matching_pcrs");
            assert_eq!(matching_pcrs.len(), 5);
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}


#[test]
fn test_boot_evidence_custom_policy() {
    let input = read_test_input("boot_evidence.json");
    let policy = read_test_policy("boot_evidence_custom.rego");

    let result = evaluate_policy(&input, &policy).expect("Policy evaluation failed");
    // The policy outputs everything under the 'result' key
    let result_obj = &result;

    // Validate attestation_valid is a bool
    let attestation_valid = result_obj["attestation_valid"].as_bool().expect("Missing or invalid 'attestation_valid'");
    // (Optionally, assert the expected value for your test input)
    assert!(!attestation_valid, "attestation_valid should be false");

    // Validate custom_data fields
    let custom_data = result_obj["custom_data"].as_object().expect("Missing or invalid 'custom_data'");

    // Validate hash_alg
    let hash_alg = custom_data["hash_alg"].as_str().expect("Missing or invalid 'hash_alg'");
    assert_eq!(hash_alg, "sha256");
}

#[test]
fn test_boot_evidence_export_policy() {
    let input = read_test_input("boot_evidence.json");
    let policy = read_test_policy("boot_evidence_export.rego");

    let result = evaluate_policy(&input, &policy).expect("Policy evaluation failed");

    // Use the result directly (no "result" key)
    let result_obj = &result;

    // Validate secure_boot: should be "disabled" for this input
    let secure_boot = result_obj["secure_boot"].as_str().expect("Missing or invalid 'secure_boot'");
    assert_eq!(secure_boot, "disabled", "secure_boot should be 'disabled'");

    // Validate is_log_valid: should be true
    let is_log_valid = result_obj["is_log_valid"].as_bool().expect("Missing or invalid 'is_log_valid'");
    assert!(is_log_valid, "is_log_valid should be true");

    // Validate pcrs: should match input.evidence.pcrs
    let expected_pcrs = &input["evidence"]["pcrs"];
    assert_eq!(&result_obj["pcrs"], expected_pcrs, "pcrs output mismatch");
}

#[test]
fn test_ima_evidence_custom_policy() {
    let input = read_test_input("ima_evidence.json");
    let policy = read_test_policy("ima_evidence_custom.rego");

    let result = evaluate_policy(&input, &policy).expect("Policy evaluation failed");

    // The policy outputs everything under the 'result' key
    let result_obj = &result;

    // Validate attestation_valid is a bool
    let attestation_valid = result_obj["attestation_valid"].as_bool().expect("Missing or invalid 'attestation_valid'");
    // (Optionally, assert the expected value for your test input)
    assert!(attestation_valid, "attestation_valid should be true");

    // Validate custom_data fields
    let custom_data = result_obj["custom_data"].as_object().expect("Missing or invalid 'custom_data'");

    // Validate hash_alg
    let hash_alg = custom_data["hash_alg"].as_str().expect("Missing or invalid 'hash_alg'");
    assert_eq!(hash_alg, "sha256");
}

#[test]
fn test_ima_evidence_export_policy() {
    let input = read_test_input("ima_evidence.json");
    let policy = read_test_policy("ima_evidence_export.rego");

    let result = evaluate_policy(&input, &policy).expect("Policy evaluation failed");

    // Use the result directly (no "result" key)
    let result_obj = &result;

    // Validate is_log_valid: should be true
    let is_log_valid = result_obj["is_log_valid"].as_bool().expect("Missing or invalid 'is_log_valid'");
    assert!(is_log_valid, "is_log_valid should be true");

    // Validate pcrs: should match input.evidence.pcrs
    let expected_pcrs = &input["evidence"]["pcrs"];
    assert_eq!(&result_obj["pcrs"], expected_pcrs, "pcrs output mismatch");
}