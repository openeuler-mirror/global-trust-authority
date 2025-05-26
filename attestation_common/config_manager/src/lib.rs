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

/// Configuration management module for loading and accessing application configuration.
///
/// This module provides a thread-safe singleton pattern for managing configuration data
/// loaded from YAML files. It uses Rust's `OnceLock` to ensure thread safety and
/// proper initialization semantics.
///
/// # Features
///
/// * Thread-safe configuration access
/// * Singleton pattern to ensure configuration is loaded only once
/// * Support for default values and optional fields
/// * Strong typing through deserialization to user-defined structs
///
/// # Example
///
/// ```
/// use serde::Deserialize;
///
/// use config_manager::ConfigSingleton;
///
/// #[derive(Deserialize)]
/// struct AppConfig {
///     app_name: String,
///     #[serde(default)]
///     port: u16,
///     #[serde(default = "default_log_level")]
///     log_level: String,
/// }
///
/// fn default_log_level() -> String {
///     "info".to_string()
/// }
///
/// // Create and initialize the config
/// let config = ConfigSingleton::<AppConfig>::new();
/// config.initialize("config.yaml").expect("Failed to load config");
///
/// // Access the configuration
/// let app_config = config.get_instance().expect("Config not initialized");
/// println!("App running: {} on port {}", app_config.app_name, app_config.port);
/// ```
pub mod manager;
pub mod types;

// Re-export key struct
pub use manager::ConfigSingleton;