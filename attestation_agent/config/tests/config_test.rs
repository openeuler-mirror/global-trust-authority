#![allow(unused_imports)]

use config::config::{Config, PluginParams};
use config::ConfigManager;
use config::AGENT_CONFIG;
use std::env;
use std::fs;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

/// Create a valid configuration YAML string
///
/// Returns a valid configuration string containing all required fields for testing normal configuration loading
fn create_valid_config_yaml() -> String {
    r#"
agent:
  listen_address: "127.0.0.1"
  listen_port: 8080
  uuid: "test-agent-001"

server:
  server_url: "https://attestation-server.example.com"
  timeout_seconds: 30
  tls:
    enabled: true
    cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
    ca_path: "/path/to/ca.pem"
plugins:
  - name: "tpm-plugin"
    path: "/usr/lib/plugins/tpm.so"
    policy_id: ["tpm_policy_id1", "tpm_policy_id2"]
    enabled: true
    params:
      attester_type: tpm_boot
      tcti_config: "device"
      log_file_path: "/sys/kernel/security/tpm0/binary_bios_measurements"
  - name: "ima-plugin"
    path: "/usr/lib/plugins/ima.so"
    policy_id: ["ima_policy_id1"]
    enabled: true
    params:
      attester_type: tpm_ima
      tcti_config: "device"
      log_file_path: "/sys/kernel/security/ima/ascii_runtime_measurements"
schedulers:
  - name: "challenge"
    retry_enabled: true
    cron_expression: "*/10 * * * * *"
    initial_delay:
      min_seconds: 1
      max_seconds: 60
    max_retries: 1

  - name: "config_sync"
    retry_enabled: false
    cron_expression: "0 */5 * * * *"
logging:
  level: "info"
  file: "/home/log/agent.log"
"#
    .to_string()
}

/// Create a temporary configuration file
///
/// Writes the provided content to a temporary file and returns the file handle for testing different configurations
fn create_temp_config_file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(content.as_bytes()).expect("Failed to write config");
    file
}

/// Test that ConfigManager initializes only once and loads configuration correctly
/// Test the to_json interface for Config serialization
/// This test ensures ConfigManager can properly initialize and load a valid configuration file
/// It also verifies that all configuration items are correctly parsed, including plugin parameters
#[test]
fn test_config_manager_single_init() {
    // Prepare test configuration file
    let config_content = create_valid_config_yaml();
    let temp_file = create_temp_config_file(&config_content);
    let config_path = temp_file.path().to_str().unwrap();

    // Initialize ConfigManager and get configuration
    let config_manager = ConfigManager::new(config_path).expect("Failed to load config");
    let config = AGENT_CONFIG.get_instance().expect("Failed to get config instance");

    assert_eq!(config_manager.get_config_path(), config_path);
    // Verify basic configuration items
    assert_eq!(config.agent.listen_port, 8080);
    assert_eq!(config.server.server_url, "https://attestation-server.example.com");
    assert_eq!(config.plugins.len(), 2);
    assert_eq!(config.schedulers.len(), 2);

    // Verify TPM plugin configuration
    let tpm_plugin = &config.plugins[0];
    assert_eq!(tpm_plugin.name, "tpm-plugin");
    if let Some(PluginParams::TpmBoot(tpm_config)) = &tpm_plugin.params {
        assert_eq!(tpm_config.tpm_base.tcti_config, "device");
        assert_eq!(tpm_config.log_file_path, "/sys/kernel/security/tpm0/binary_bios_measurements");
    } else {
        panic!("Expected TPM plugin params");
    }

    // Verify IMA plugin configuration
    let ima_plugin = &config.plugins[1];
    if let Some(PluginParams::TpmIma(ima_config)) = &ima_plugin.params {
        assert_eq!(ima_config.log_file_path, "/sys/kernel/security/ima/ascii_runtime_measurements");
    } else {
        panic!("Expected IMA plugin params");
    }

    // Serialize config to JSON
    let json_str = ConfigManager::to_json(&config).expect("Failed to serialize config to JSON");
    // Optionally: print JSON for debug
    // println!("Config JSON: {}", json_str);

    // Parse back to serde_json::Value for field checking
    let json_value: serde_json::Value = serde_json::from_str(&json_str).expect("JSON parse error");
    // Check some key fields
    assert_eq!(json_value["agent"]["listen_port"], 8080);
    assert_eq!(json_value["server"]["server_url"], "https://attestation-server.example.com");
    assert_eq!(json_value["plugins"].as_array().unwrap().len(), 2);
    assert_eq!(json_value["schedulers"].as_array().unwrap().len(), 2);
}