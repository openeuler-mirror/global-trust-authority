use tpm_ima_verifier::TpmImaPlugin;
use plugin_manager::{ServicePlugin, PluginError, ServiceHostFunctions};
use tpm_common_verifier::{PcrValues, Logs, PcrValueEntry, GenerateEvidence};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

fn mock_query_configuration(_key: String) -> Option<String> {
    None
}

// Create a function to get service host functions for testing
fn get_test_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions::new(
        Box::new(|_user_id, _node_id, _cert_chain| Box::pin(async { true })),
        Box::new(|_hashes, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        mock_query_configuration
    )
}

#[test]
fn test_tpm_ima_plugin_creation() {
    // Create plugin
    let plugin = TpmImaPlugin::new(String::from("tpm_ima"), get_test_host_functions());
    
    // Verify sample output
    let sample_output = plugin.get_sample_output();
    assert!(sample_output.is_object());
    assert!(sample_output.get("evidence").is_some());
}

#[tokio::test]
async fn test_generate_evidence_with_valid_log() {
    // Create a simple valid IMA log
    let log_str = "10 be00517f0f1e46f33a39e0a2c21f8f0ae681c647 ima-ng sha256:0ffb68384766c27acb35e1ed0b4a04f3e9d456f131db842feecbeb5d4d543a8a boot_aggregate";
    let encoded_log = BASE64.encode(log_str);
    
    // Create logs vector
    let logs = vec![Logs {
        log_type: "tpm_ima".to_string(),
        log_data: encoded_log,
    }];
    
    // Create PCR values
    let mut pcr_values = PcrValues {
        hash_alg: "sha256".to_string(),
        pcr_values: vec![PcrValueEntry {
            pcr_index: 10,
            pcr_value: "be00517f0f1e46f33a39e0a2c21f8f0ae681c647be00517f0f1e46f33a39e0a2".to_string(),
            replay_value: None,
            is_matched: None,
        }],
    };
    
    // Create service host functions
    let host_functions = get_test_host_functions();
    
    // Create plugin
    let plugin = TpmImaPlugin::new("tpm_ima".to_string(), host_functions);
    
    // Generate evidence
    let result = plugin.generate_evidence(  "test_user", &logs, &mut pcr_values).await;
    
    // Verify result
    assert!(result.is_ok());
    let evidence_json = result.unwrap();
    assert!(evidence_json.is_object());
    
    // Check if the evidence contains the evidence wrapper
    let evidence = evidence_json.get("evidence").expect("Missing evidence wrapper");
    
    // Check if the evidence contains logs
    let logs_result = evidence.get("logs").expect("Missing logs in evidence");
    assert!(logs_result.is_array());
    assert_eq!(logs_result.as_array().unwrap().len(), 1);
    
    // Check if the evidence contains PCR values
    let pcrs = evidence.get("pcrs").expect("Missing PCRs in evidence");
    assert!(pcrs.is_object());
}

#[tokio::test]
async fn test_generate_evidence_with_invalid_log_type() {
    // Create logs with invalid log type
    let logs = vec![Logs {
        log_type: "invalid_type".to_string(),
        log_data: "invalid_data".to_string(),
    }];
    
    // Create PCR values
    let mut pcr_values = PcrValues {
        hash_alg: "sha256".to_string(),
        pcr_values: vec![PcrValueEntry {
            pcr_index: 10,
            pcr_value: "be00517f0f1e46f33a39e0a2c21f8f0ae681c647be00517f0f1e46f33a39e0a2".to_string(),
            replay_value: None,
            is_matched: None,
        }],
    };
    
    // Create service host functions
    let host_functions = get_test_host_functions();
    
    // Create plugin
    let plugin = TpmImaPlugin::new("tpm_ima".to_string(), host_functions);
    
    // Generate evidence
    let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;
    
    // Verify result is an error
    assert!(result.is_err());
    match result {
        Err(PluginError::InputError(_)) => {}, // Expected error type
        _ => panic!("Expected InputError but got a different error or success")
    }
}