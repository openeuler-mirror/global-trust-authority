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

use std::fs;
use std::path::PathBuf;

use plugin_manager::{PluginError, ServiceHostFunctions, ServicePlugin};
use serde_json::{json, Value};

use virt_cca_verifier::verifier::{create_plugin, VirtCCAPlugin};

fn get_test_data_path(file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("data");
    path.push(file_name);
    path
}

fn create_default_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
        get_unmatched_measurements: Box::new(|_measured_values, _attester_type, _user_id| Box::pin(async { Ok(Vec::new()) })),
        query_configuration: |_key| None,
    }
}

#[tokio::test]
async fn test_verify_evidence_success() {
    let evidence_path = get_test_data_path("evidence.json");
    let evidence_str = fs::read_to_string(evidence_path).expect("Unable to read evidence.json");
    let mut evidence: Value = serde_json::from_str(&evidence_str).expect("Unable to parse evidence.json");
    let mut evidence_value = evidence["evidence"].take();

    // Ensure vcca_token is present for testing purposes
    if evidence_value.get("vcca_token").is_none() {
        evidence_value["vcca_token"] = Value::String("placeholder_vcca_token".to_string());
    }
    if evidence_value.get("dev_cert").is_none() {
        evidence_value["dev_cert"] = Value::String("placeholder_dev_cert".to_string());
    }
    
    if evidence_value.get("logs").is_none() {
        evidence_value["logs"] = Value::Array(vec![]);
    }

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, None).await;

    if let Err(e) = &result { println!("Verification failed: {:?}", e); }
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    let output = result.unwrap();

    assert!(output.is_object());
    assert!(output.get("vcca_rpv").is_some());
    assert!(output.get("vcca_ima_log_status").is_some());
    assert!(output.get("vcca_ccel_log_status").is_some());
}

#[tokio::test]
async fn test_verify_evidence_missing_vcca_token() {
    let mut evidence_value: Value = json!({});
    evidence_value["dev_cert"] = json!("test_cert");
    evidence_value["logs"] = json!([]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("Missing required field: vcca_token"));
    } else {
        panic!("Expected InputError for missing vcca_token");
    }
}

#[tokio::test]
async fn test_verify_evidence_invalid_vcca_token_type() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!(123);
    evidence_value["dev_cert"] = json!("test_cert");
    evidence_value["logs"] = json!([]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("vcca_token must be a string"));
    } else {
        panic!("Expected InputError for invalid vcca_token type");
    }
}

#[tokio::test]
async fn test_verify_evidence_missing_dev_cert() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!("test_token");
    evidence_value["logs"] = json!([]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("Missing required field: dev_cert"));
    } else {
        panic!("Expected InputError for missing dev_cert");
    }
}

#[tokio::test]
async fn test_verify_evidence_invalid_dev_cert_type() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!("test_token");
    evidence_value["dev_cert"] = json!(123);
    evidence_value["logs"] = json!([]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("dev_cert must be a string"));
    } else {
        panic!("Expected InputError for invalid dev_cert type");
    }
}

#[tokio::test]
async fn test_verify_evidence_invalid_logs_type() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!("test_token");
    evidence_value["dev_cert"] = json!("test_cert");
    evidence_value["logs"] = json!("invalid_logs_type");

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("logs must be an array"));
    } else {
        panic!("Expected InputError for invalid logs type");
    }
}

#[tokio::test]
async fn test_verify_evidence_missing_log_type() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!("test_token");
    evidence_value["dev_cert"] = json!("test_cert");
    evidence_value["logs"] = json!([
        {
            "log_data": "test_log"
        }
    ]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_type must be a string"));
    } else {
        panic!("Expected InputError for missing log_type");
    }
}

#[tokio::test]
async fn test_verify_evidence_invalid_log_type_type() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!("test_token");
    evidence_value["dev_cert"] = json!("test_cert");
    evidence_value["logs"] = json!([
        {
            "log_type": 123,
            "log_data": "test_log"
        }
    ]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_type must be a string"));
    } else {
        panic!("Expected InputError for invalid log_type type");
    }
}

#[tokio::test]
async fn test_verify_evidence_missing_log_data() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!("test_token");
    evidence_value["dev_cert"] = json!("test_cert");
    evidence_value["logs"] = json!([
        {
            "log_type": "ImaLog"
        }
    ]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_data must be a string"));
    } else {
        panic!("Expected InputError for missing log_data");
    }
}

#[tokio::test]
async fn test_verify_evidence_invalid_log_data_type() {
    let mut evidence_value: Value = json!({});
    evidence_value["vcca_token"] = json!("test_token");
    evidence_value["dev_cert"] = json!("test_cert");
    evidence_value["logs"] = json!([
        {
            "log_type": "ImaLog",
            "log_data": 123
        }
    ]);

    let host_functions = create_default_host_functions();
    let plugin_type = "virt_cca";
    let plugin = create_plugin(host_functions, plugin_type).expect("Failed to create plugin");

    let user_id = "test_user";
    let node_id = Some("test_node");
    let nonce = Some(b"test_nonce" as &[u8]);

    let result = plugin.verify_evidence(user_id, node_id, &evidence_value, nonce).await;

    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_data must be a string"));
    } else {
        panic!("Expected InputError for invalid log_data type");
    }
}

#[tokio::test]
async fn test_verify_evidence_invalid_plugin_type() {
    let host_functions = create_default_host_functions();
    let plugin_type = "invalid_type";
    let result = create_plugin(host_functions, plugin_type);

    assert!(result.is_err());
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(err_msg.contains("Invalid plugin type"));
    } else {
        panic!("Expected error for invalid plugin type");
    }
}

#[tokio::test]
async fn test_get_sample_output() {
    let host_functions = create_default_host_functions();
    let plugin = VirtCCAPlugin::new("virt_cca".to_string(), host_functions);
    let sample_output = plugin.get_sample_output();

    assert!(sample_output.is_object());
    assert!(sample_output.get("evidence").is_some());
    assert!(sample_output["evidence"].get("vcca_token").is_some());
    assert!(sample_output["evidence"].get("dev_cert").is_some());
    assert!(sample_output["evidence"].get("logs").is_some());
}