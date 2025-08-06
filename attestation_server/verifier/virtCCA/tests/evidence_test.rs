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

use plugin_manager::PluginError;
use serde_json::{json, Value};

use virt_cca_verifier::evidence::VritCCAEvidence;

fn get_test_data_path(file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("data");
    path.push(file_name);
    path
}

#[test]
fn test_vritcca_evidence_from_json_value_success() {
    let evidence_path = get_test_data_path("evidence.json");
    let evidence_str = fs::read_to_string(evidence_path).expect("Unable to read evidence.json");
    let full_evidence_json: Value = serde_json::from_str(&evidence_str).expect("Unable to parse evidence.json");
    let evidence_value = full_evidence_json["evidence"].clone();

    let result = VritCCAEvidence::from_json_value(&evidence_value);
    assert!(result.is_ok(), "Failed to parse VritCCAEvidence: {:?}", result.err());
    let evidence = result.unwrap();

    assert_eq!(evidence.vcca_token, evidence_value["vcca_token"].as_str().unwrap());
    assert_eq!(evidence.dev_cert, evidence_value["dev_cert"].as_str().unwrap());
    assert!(evidence.logs.is_some());
    assert_eq!(evidence.logs.unwrap().len(), evidence_value["logs"].as_array().unwrap().len());
}

#[test]
fn test_vritcca_evidence_from_json_value_missing_vcca_token() {
    let json_value = json!({
        "dev_cert": "test_dev_cert",
        "logs": []
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("Missing required field: vcca_token"));
    } else {
        panic!("Expected InputError for missing vcca_token");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_missing_dev_cert() {
    let json_value = json!({
        "vcca_token": "test_vcca_token",
        "logs": []
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("Missing required field: dev_cert"));
    } else {
        panic!("Expected InputError for missing dev_cert");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_invalid_vcca_token_type() {
    let json_value = json!({
        "vcca_token": 123,
        "dev_cert": "test_dev_cert",
        "logs": []
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("vcca_token must be a string"));
    } else {
        panic!("Expected InputError for invalid vcca_token type");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_invalid_dev_cert_type() {
    let json_value = json!({
        "vcca_token": "test_vcca_token",
        "dev_cert": 123,
        "logs": []
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("dev_cert must be a string"));
    } else {
        panic!("Expected InputError for invalid dev_cert type");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_invalid_logs_type() {
    let json_value = json!({
        "vcca_token": "test_vcca_token",
        "dev_cert": "test_dev_cert",
        "logs": "invalid_type"
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("logs must be an array"));
    } else {
        panic!("Expected InputError for invalid logs type");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_missing_log_type() {
    let json_value = json!({
        "vcca_token": "test_vcca_token",
        "dev_cert": "test_dev_cert",
        "logs": [
            {
                "log_data": "test_log_data"
            }
        ]
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_type must be a string"));
    } else {
        panic!("Expected InputError for missing log_type");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_invalid_log_type_type() {
    let json_value = json!({
        "vcca_token": "test_vcca_token",
        "dev_cert": "test_dev_cert",
        "logs": [
            {
                "log_type": 123,
                "log_data": "test_log_data"
            }
        ]
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_type must be a string"));
    } else {
        panic!("Expected InputError for invalid log_type type");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_missing_log_data() {
    let json_value = json!({
        "vcca_token": "test_vcca_token",
        "dev_cert": "test_dev_cert",
        "logs": [
            {
                "log_type": "ImaLog"
            }
        ]
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_data must be a string"));
    } else {
        panic!("Expected InputError for missing log_data");
    }
}

#[test]
fn test_vritcca_evidence_from_json_value_invalid_log_data_type() {
    let json_value = json!({
        "vcca_token": "test_vcca_token",
        "dev_cert": "test_dev_cert",
        "logs": [
            {
                "log_type": "ImaLog",
                "log_data": 123
            }
        ]
    });

    let result = VritCCAEvidence::from_json_value(&json_value);
    assert!(result.is_err());
    if let Err(PluginError::InputError(msg)) = result {
        assert!(msg.contains("log_data must be a string"));
    } else {
        panic!("Expected InputError for invalid log_data type");
    }
}