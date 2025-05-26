use tpm_dim_verifier::dim_verifier::TpmDimPlugin;
use tpm_common_verifier::{GenerateEvidence, PcrValues, Logs};
use plugin_manager::{ServiceHostFunctions, ServicePlugin};
use base64::Engine;

// 构造一个简单的 ServiceHostFunctions 用于测试
fn create_mock_service_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions {
        get_unmatched_measurements: Box::new(|_file_hashes, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
        validate_cert_chain: Box::new(|_plugin_type, _user_id, _cert_chain| Box::pin(async { true })),
    }
}

#[tokio::test]
async fn test_generate_evidence_success() {
    let plugin = TpmDimPlugin::new("tpm_dim".to_string(), create_mock_service_host_functions());
    let mut pcr_values = PcrValues::new();
    pcr_values.hash_alg = "sha256".to_string();
    let initial_value = PcrValues::create_initial_pcr_value("sha256", 0, None).unwrap();
    pcr_values.set_pcr_value(0, initial_value);
    let log_content = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02 test_file [static baseline]";
    let log_data = base64::engine::general_purpose::STANDARD.encode(log_content);
    let logs = vec![Logs { log_type: "tpm_dim".to_string(), log_data }];
    let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;
    assert!(result.is_ok());
    let json = result.unwrap();
    assert!(json.is_object());
}

#[tokio::test]
async fn test_generate_evidence_empty_logs() {
    let plugin = TpmDimPlugin::new("tpm_dim".to_string(), create_mock_service_host_functions());
    let mut pcr_values = PcrValues::new();
    let logs: Vec<Logs> = vec![];
    let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_generate_evidence_multiple_logs() {
    let plugin = TpmDimPlugin::new("tpm_dim".to_string(), create_mock_service_host_functions());
    let mut pcr_values = PcrValues::new();
    let log_content = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02 test_file [static baseline]";
    let log_data = base64::engine::general_purpose::STANDARD.encode(log_content);
    let logs = vec![
        Logs { log_type: "tpm_dim".to_string(), log_data: log_data.clone() },
        Logs { log_type: "tpm_dim".to_string(), log_data }
    ];
    let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_generate_evidence_invalid_log_type() {
    let plugin = TpmDimPlugin::new("tpm_dim".to_string(), create_mock_service_host_functions());
    let mut pcr_values = PcrValues::new();
    let log_content = "0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sha256:5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02 test_file [static baseline]";
    let log_data = base64::engine::general_purpose::STANDARD.encode(log_content);
    let logs = vec![Logs { log_type: "invalid_type".to_string(), log_data }];
    let result = plugin.generate_evidence("test_user", &logs, &mut pcr_values).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_verify_evidence_invalid_json() {
    let plugin = TpmDimPlugin::new("tpm_dim".to_string(), create_mock_service_host_functions());
    let invalid_json = serde_json::json!({ "invalid": "data" });
    let result = plugin.verify_evidence("test_user", None, &invalid_json, None).await;
    assert!(result.is_err());
}
