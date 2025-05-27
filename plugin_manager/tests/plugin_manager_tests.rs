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

/// Integration tests for the plugin-interface crate

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use plugin_manager::PluginManager;
use plugin_manager::ServiceHostFunctions;
use plugin_manager::ServicePlugin;
use plugin_manager::PluginManagerInstance;

// Simulate an async certificate validation
async fn async_validate_cert_chain(cert_data: &[u8]) -> bool {
    // Simulate I/O or async work
    use tokio::time::{sleep, Duration};
    sleep(Duration::from_millis(10)).await;
    !cert_data.is_empty()
}

async fn async_get_unmatched_measurements(measured_values: &Vec<String>, _attester_type: &str, _user_id: &str) -> Result<Vec<String>, String> {
    Ok(measured_values.clone())
}

// Mock implementation of ServiceHostFunctions for testing
fn create_test_host_functions() -> ServiceHostFunctions {
    ServiceHostFunctions {
        validate_cert_chain: Box::new(|_, _, cert_data| Box::pin(async_validate_cert_chain(cert_data))),
        get_unmatched_measurements: Box::new(|measured_values, _, _| Box::pin(async_get_unmatched_measurements(measured_values, "", ""))),
        query_configuration: |s| if s == "test" { Some("test".to_string()) } else { Some("default".to_string()) },
    }
}

// Get the platform-specific library filename
fn get_platform_lib_filename(name: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        format!("{}.dll", name)
    }
    
    #[cfg(target_os = "linux")]
    {
        format!("lib{}.so", name)
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        compile_error!("Unsupported platform for tests")
    }
}

// Helper to build the mock plugin
fn build_mock_plugin() -> Result<PathBuf, String> {
    // Get the path to the mock plugin source
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => dir,
        Err(_) => return Err("CARGO_MANIFEST_DIR not set".to_string()),
    };
    
    // Use platform-agnostic path joining
    let mock_plugin_dir = Path::new(&manifest_dir).join("tests").join("mock_plugin_for_service");
    
    if !mock_plugin_dir.exists() {
        return Err(format!("Mock plugin directory not found at {:?}", mock_plugin_dir));
    }
    
    // Check if Cargo.toml exists
    let cargo_toml = mock_plugin_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(format!("Cargo.toml not found at {:?}", cargo_toml));
    }
    
    // Build the mock plugin
    // Use platform-agnostic cargo command
    let cargo = if cfg!(windows) { "cargo.exe" } else { "cargo" };
    
    let output = match Command::new(cargo)
        .args(["build", "--release"])
        .current_dir(&mock_plugin_dir)
        .output() {
            Ok(output) => output,
            Err(e) => return Err(format!("Failed to execute cargo build: {}", e)),
        };
    
    if !output.status.success() {
        return Err(format!("Failed to build mock plugin: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }
    
    // Return the path to the built plugin library using platform-specific naming
    let target_dir = mock_plugin_dir.join("target").join("release");
    
    let lib_filename = get_platform_lib_filename("mock_plugin_for_service");
    
    let lib_path = target_dir.join(lib_filename);
    
    if !lib_path.exists() {
        return Err(format!("Plugin library not found at {:?}", lib_path));
    }
    
    Ok(lib_path)
}

#[tokio::test]
async fn test_plugin_manager_load() {
    // Build the mock plugin
    let plugin_path = build_mock_plugin()
        .unwrap_or_else(|err| panic!("Failed to build mock plugin: {}", err));
    
    // Create a HashMap with the plugin path
    let mut plugin_paths = HashMap::new();
    plugin_paths.insert("mock_plugin_for_service".to_string(), plugin_path.to_string_lossy().to_string());
    
    // Get the host functions
    let host_functions = create_test_host_functions();
    
    // Get the plugin manager instance
    let manager = PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance();
    
    // Check if the plugin manager is initialized
    assert!(!manager.is_initialized());

    // Initialize the plugin manager
    assert!(manager.initialize(&plugin_paths, &host_functions));
    
    // Check if the plugin manager is initialized
    assert!(manager.is_initialized());
    
    // Get the plugin types
    let plugin_types = manager.get_plugin_types();
    assert_eq!(plugin_types.len(), 1);
    assert_eq!(plugin_types[0], "mock_plugin_for_service");
    
    // Get the plugin
    let plugin = manager.get_plugin("mock_plugin_for_service");
    assert!(plugin.is_some());
    
    // Test the plugin
    let plugin = plugin.unwrap();
    assert_eq!(plugin.plugin_type(), "mock_plugin_for_service");
    assert_eq!(plugin.get_sample_output(), serde_json::json!({
        "cert_verification_result": true,
        "unmatched_value": ["test"],
        "config": "test"
    }));
    // Test parse_evidence
    let evidence = serde_json::json!({
        "cert_verification_result": true,
        "unmatched_value": ["test"],
        "config": "test"
    });
    let parsed = plugin.verify_evidence("", None, &evidence, None).await;
    assert!(parsed.is_ok());
    assert_eq!(parsed.unwrap(), evidence);
}

#[test]
fn test_plugin_manager_load_error() {
    // Create a HashMap with a non-existent plugin path
    let mut plugin_paths = HashMap::new();
    plugin_paths.insert("non_existent_plugin".to_string(), "non_existent_path".to_string());
    
    // Get the host functions
    let host_functions = create_test_host_functions();
    
    // Get the plugin manager instance
    let manager = PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance();
    
    // Initialize the plugin manager
    assert!(!manager.initialize(&plugin_paths, &host_functions));
    
    // Check if the plugin manager is initialized
    assert!(!manager.is_initialized());
    
    // Get the plugin types
    let plugin_types = manager.get_plugin_types();
    assert_eq!(plugin_types.len(), 0);
    
    // Get the plugin
    let plugin = manager.get_plugin("non_existent_plugin");
    assert!(plugin.is_none());
}
