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

use serde::Deserialize;
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;
use std::sync::OnceLock;

/// A thread-safe singleton configuration manager that loads and provides access to configuration data.
/// 
/// This struct uses Rust's `OnceLock` to ensure that configuration is initialized only once
/// and can be safely accessed from multiple threads. It supports deserializing configuration
/// from YAML files into any type that implements the `Deserialize` trait.
/// 
/// # Type Parameters
/// 
/// * `T` - The configuration type that must implement `Deserialize`, `Send`, `Sync`, and have a static lifetime.
pub struct ConfigSingleton<T: for<'a> Deserialize<'a> + Send + Sync + 'static> {
    instance: OnceLock<T>,
}

impl <T: for<'a> Deserialize<'a> + Send + Sync + 'static> ConfigSingleton<T> {
    /// Creates a new, uninitialized `ConfigSingleton` instance.
    /// 
    /// This constructor does not load any configuration data. You must call
    /// `initialize` before accessing the configuration with `get_instance`.
    pub const fn new() -> Self {
        ConfigSingleton {
            instance: OnceLock::new(),
        }
    }

    /// Initializes the configuration singleton by loading and parsing a YAML configuration file.
    /// 
    /// This method will load the file at the given path, parse it as YAML, and store the
    /// resulting configuration. If the singleton has already been initialized, this method
    /// will return `Ok(())` without changing the existing configuration.
    /// 
    /// # Parameters
    /// 
    /// * `path` - A path to the YAML configuration file.
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` if initialization was successful or if the singleton was already initialized.
    /// * `Err(String)` if there was an error opening, reading, or parsing the configuration file.
    /// 
    /// # Errors
    /// 
    /// This function will return an error if:
    /// * The file cannot be opened (e.g., it doesn't exist or permissions are insufficient)
    /// * The file cannot be read
    /// * The YAML content cannot be parsed into the target type `T`
    pub fn initialize<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        if self.instance.get().is_some() {
            return Ok(());
        }
        
        let file = File::open(path).map_err(|e| format!("Failed to open config file: {}", e))?;
        
        let mut contents = String::new();
        let mut reader = BufReader::new(file);
        reader.read_to_string(&mut contents).map_err(|e| format!("Failed to read config file: {}", e))?;
        
        let config = serde_yaml::from_str(&contents).map_err(|e| format!("Failed to parse YAML: {}", e))?;
        
        // If the config type is ServerConfig, validate it before setting
        if let Some(server_config) = (&config as &dyn std::any::Any).downcast_ref::<crate::types::context::ServerConfig>() {
            server_config.validate();
        }
        
        let _ = self.instance.set(config);
        Ok(())
    }

    /// Retrieves a reference to the initialized configuration instance.
    /// 
    /// # Returns
    /// 
    /// * `Ok(&T)` - A reference to the configuration if it has been initialized.
    /// * `Err(String)` - An error message if the configuration has not been initialized.
    /// 
    /// # Errors
    /// 
    /// Returns an error if `initialize` has not been called successfully before calling this method.
    pub fn get_instance(&self) -> Result<&T, String> {
        self.instance.get().ok_or_else(|| "Configuration not initialized".to_string())
    }
}