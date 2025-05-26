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

use std::{env, fmt};
use std::path::{Path, PathBuf};
use log::warn;
use serde_yaml::{Mapping, Value};

#[derive(Debug, Clone)]
pub struct YamlValue(pub Value);

impl YamlValue {
    /// Parse YAML from a file
    pub fn from_default_yaml() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(Path::new("server_config.yaml"))
            .display()
            .to_string();
        let contents = std::fs::read_to_string(config_path)?;
        let value: Value = serde_yaml::from_str(&contents)?;
        Ok(YamlValue(value))
    }
    
    /// Parse YAML from a file
    pub fn from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(file_path)?;
        let value: Value = serde_yaml::from_str(&contents)?;
        Ok(YamlValue(value))
    }

    /// Parsing YAML from strings
    pub fn from_str(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let value: Value = serde_yaml::from_str(content)?;
        Ok(YamlValue(value))
    }

    /// Get field value
    pub fn get(&self, key: &str) -> Option<YamlValue> {
        let value = self.0.get(key).map(|v| YamlValue(v.clone()));
        if value.is_none() {
            warn!("Yaml parse Missing key: {}", key);
        }
        value
    }
    
    pub fn get_nested(&self, key: &str) -> Option<YamlValue> {
        let keys: Vec<&str> = key.split('.').collect();
        let mut current = &self.0;
        for k in keys {
            if let Some(value) = current.get(k) {
                current = value;
            } else {
                warn!("Yaml parse Missing key: {}", k);
                return None;
            }
        }
        Some(YamlValue(current.clone()))
    }

    /// Convert to string
    pub fn as_str(&self) -> Option<&str> {
        self.0.as_str()
    }
    
    /// Convert to ownership string
    pub fn as_string(&self) -> Option<String> {
        self.0.as_str().map(|s| s.to_string())
    }

    /// Convert to Boolean
    pub fn as_bool(&self) -> Option<bool> {
        self.0.as_bool()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.0.as_u64()
    }

    /// Convert to float
    pub fn as_f64(&self) -> Option<f64> {
        self.0.as_f64()
    }

    /// Convert to Array
    pub fn as_array(&self) -> Option<Vec<Value>> {
        self.0.as_sequence().cloned()
    }

    /// Convert to map
    pub fn as_map(&self) -> Option<Mapping> {
        self.0.as_mapping().cloned()
    }
}

impl fmt::Display for YamlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        serde_yaml::to_string(&self.0)
            .map_err(|_| fmt::Error)
            .and_then(|s| write!(f, "{}", s))
    }
}

// macro definition
#[macro_export]
macro_rules! yaml_get {
    ($value:expr, $path:expr => str) => {{
        (|| -> Option<String> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = current.get(key)?;
            }
            current.as_string()
        })()
    }};
    ($value:expr, $path:expr => bool) => {{
        (|| -> Option<bool> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = current.get(key)?;
            }
            current.as_bool()
        })()
    }};
    ($value:expr, $path:expr => u64) => {{
        (|| -> Option<u64> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = current.get(key)?;
            }
            current.as_u64()
        })()
    }};
    ($value:expr, $path:expr => f64) => {{
        (|| -> Option<f64> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = current.get(key)?;
            }
            current.as_f64()
        })()
    }};
    ($value:expr, $path:expr => array) => {{
        (|| -> Option<Vec<Value>> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = current.get(key)?;
            }
            current.as_array()
        })()
    }};
    ($value:expr, $path:expr => map) => {{
        (|| -> Option<serde_yaml::Mapping> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = current.get(key)?;
            }
            current.as_map()
        })()
    }};
    ($value:expr, $path:expr => str, or $default:expr) => {{
        (|| -> Option<String> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = match current.get(key) {
                    Some(c) => c,
                    None => return Some($default.to_string()),
                };
            }
            current.as_string().or(Some($default.to_string()))
        })()
    }};
    ($value:expr, $path:expr => bool, or $default:expr) => {{
        (|| -> Option<bool> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = match current.get(key) {
                    Some(c) => c,
                    None => return Some($default),
                };
            }
            current.as_bool().or(Some($default))
        })()
    }};
    ($value:expr, $path:expr => u64, or $default:expr) => {{
        (|| -> Option<u64> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = match current.get(key) {
                    Some(c) => c,
                    None => return Some($default),
                };
            }
            current.as_u64().or(Some($default))
        })()
    }};
    ($value:expr, $path:expr => f64, or $default:expr) => {{
        (|| -> Option<f64> {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = match current.get(key) {
                    Some(c) => c,
                    None => return Some($default),
                };
            }
            current.as_f64().or(Some($default))
        })()
    }};
    // Support for custom conversion logic
    ($value:expr, $path:expr => custom $closure:expr) => {{
        (|| {
            let path = $path;
            let keys: Vec<&str> = path.split('.').collect();
            let mut current = $value;
            for key in keys {
                current = current.get(key)?;
            }
            $closure(&current)
        })()
    }};
}