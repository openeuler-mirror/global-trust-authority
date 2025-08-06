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

use virtcca_attester::VirtCCAPlugin;
use plugin_manager::PluginError;
use tempfile::NamedTempFile;
use std::io::Write;
use base64::{engine::general_purpose, Engine as _};
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref TEST_CONFIG: Mutex<Option<String>> = Mutex::new(None);
}

fn set_test_config(config: Option<String>) {
    *TEST_CONFIG.lock().unwrap() = config;
}

fn query_configuration(_plugin_type: String) -> Option<String> {
    TEST_CONFIG.lock().unwrap().clone()
}

fn build_config_json(ima_path: &str, ccel_path: &str) -> String {
    serde_json::json!({
        "plugin_type": "virt_cca",
        "ima_log_file_path": ima_path,
        "ccel_data_path": ccel_path
    })
    .to_string()
}

#[test]
fn test_plugin_new_success_and_collect_log() {
    // Prepare temporary IMA log file
    let mut ima_file = NamedTempFile::new().expect("create ima temp file");
    writeln!(ima_file, "ima test line1").unwrap();
    writeln!(ima_file, "ima test line2").unwrap();

    // Prepare temporary CCEL data file
    let mut ccel_file = NamedTempFile::new().expect("create ccel temp file");
    ccel_file.write_all(b"ccel_binary_data").unwrap();

    // Build configuration JSON with the generated file paths
    let config_json = build_config_json(
        ima_file.path().to_str().unwrap(),
        ccel_file.path().to_str().unwrap(),
    );

    set_test_config(Some(config_json));

    let plugin = VirtCCAPlugin::new(
        "virt_cca".to_string(),
        query_configuration,
    )
    .expect("plugin should be created successfully");

    // Collect all logs
    let logs_opt = plugin
        .collect_log(None)
        .expect("collect_log should succeed");
    let logs = logs_opt.expect("logs should not be None");
    assert_eq!(logs.len(), 2);

    // Validate log types and content
    for log in logs {
        match log.log_type.as_str() {
            "ImaLog" => {
                let decoded = String::from_utf8(
                    general_purpose::STANDARD
                        .decode(log.log_data)
                        .expect("base64 decode ima"),
                )
                .unwrap();
                assert!(decoded.contains("ima test line1"));
            }
            "CCEL" => {
                let decoded = general_purpose::STANDARD
                    .decode(log.log_data)
                    .expect("base64 decode ccel");
                assert_eq!(decoded, b"ccel_binary_data");
            }
            other => panic!("unexpected log type {other}"),
        }
    }
}

#[test]
fn test_plugin_new_invalid_type() {
    let plugin = VirtCCAPlugin::new("wrong_type".to_string(), query_configuration);
    assert!(matches!(plugin, Err(PluginError::InputError(_))));
}

#[test]
fn test_plugin_config_not_found() {
    set_test_config(None::<String>);

    let result = VirtCCAPlugin::new("virt_cca".to_string(), query_configuration);
    assert!(matches!(result, Err(PluginError::InternalError(msg)) if msg == "Plugin configuration not found"));
}

#[test]
fn test_config_from_json_success() {
    let json = build_config_json("/path/ima", "/path/ccel");
    let cfg = virtcca_attester::config::VirtCCAConfig::from_json("virt_cca".to_string(), &json)
        .expect("parse json");
    assert_eq!(cfg.ima_log_file_path, "/path/ima");
    assert_eq!(cfg.ccel_data_path, "/path/ccel");
}