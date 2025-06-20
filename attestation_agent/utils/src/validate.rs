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

pub mod validate_utils {
    use crate::agent_error::AgentError;
    use regex::Regex;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::Path;
    use validator::ValidationError;

    /// Validates a file path and its accessibility.
    ///
    /// This function performs the following checks:
    /// 1. Checks if the path is empty
    /// 2. Checks if the file exists
    /// 3. Checks if the path points to a file (not a directory)
    /// 4. Checks if the file is readable
    ///
    /// # Arguments
    ///
    /// * `path` - A string slice that holds the file path to validate
    ///
    /// # Returns
    ///
    /// * `Result<(), ValidationError>` - Returns `Ok(())` if all validations pass,
    ///   otherwise returns a `ValidationError` with an appropriate error message.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` in the following cases:
    /// * Path is empty
    /// * File does not exist
    /// * Path is not a file
    /// * File is not readable
    pub fn validate_file(path: &str) -> Result<(), ValidationError> {
        // Check if path is empty
        if path.is_empty() {
            return Err(ValidationError::new("Path is empty"));
        }

        let path_obj = Path::new(path);

        // Check if file exists
        if !path_obj.exists() {
            return Err(ValidationError::new("File not found"));
        }

        // Check if it's a file
        if !path_obj.is_file() {
            return Err(ValidationError::new("Path is not a file"));
        }

        // Check if file is readable
        if fs::metadata(path_obj).and_then(|metadata| {
            if metadata.permissions().readonly() {
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "File is not readable"))
            } else {
                Ok(())
            }
        }).is_err() {
            return Err(ValidationError::new("Cannot read file"));
        }

        Ok(())
    }

    /// Validates a bind address string for server configuration.
    ///
    /// This function checks if the provided address is a valid:
    /// - IPv4 address (e.g., "127.0.0.1")
    /// - IPv6 address (e.g., "`::1`")
    /// - Hostname (e.g., "localhost", "example.com")
    ///
    /// # Arguments
    ///
    /// * `address` - A reference to a string containing the address to validate
    ///
    /// # Returns
    ///
    /// * `Result<(), ValidationError>` - Returns `Ok(())` if the address is valid,
    ///   otherwise returns a `ValidationError` with an appropriate error message.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if:
    /// * The address is not a valid IPv4 address
    /// * The address is not a valid IPv6 address
    /// * The address is not a valid hostname (doesn't match the hostname regex pattern)
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(validate_bind_address(&"127.0.0.1".to_string()).is_ok());
    /// assert!(validate_bind_address(&"::1".to_string()).is_ok());
    /// assert!(validate_bind_address(&"localhost".to_string()).is_ok());
    /// assert!(validate_bind_address(&"invalid".to_string()).is_err());
    /// ```
    pub fn validate_bind_address(address: &&String) -> Result<(), ValidationError> {
        // Check if it's a valid IPv4 address
        if let Ok(_ipv4) = address.parse::<Ipv4Addr>() {
            return Ok(());
        }

        // Check if it's a valid IPv6 address
        if let Ok(_ipv6) = address.parse::<Ipv6Addr>() {
            return Ok(());
        }

        // Check if it's a valid hostname
        let hostname_regex = Regex::new(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        )
        .map_err(|_e| {
            ValidationError::new("Failed to compile hostname validation pattern")
        })?;

        if hostname_regex.is_match(address) {
            return Ok(());
        }

        Err(ValidationError::new("Invalid bind address. Must be a valid IPv4, IPv6 address or hostname"))
    }

    /// Validates a REST API route path string.
    ///
    /// This function performs comprehensive validation of a REST API route path, including:
    /// - Path must not be empty
    /// - Path must start with '/'
    /// - No control characters allowed
    /// - No query parameters or fragments allowed
    /// - Proper parameter placeholder syntax (e.g., "/users/{id}")
    /// - No nested braces
    /// - No duplicate parameter names
    /// - Parameter names must be alphanumeric or underscore
    ///
    /// # Arguments
    ///
    /// * `rest_path` - A string slice containing the route path to validate
    ///
    /// # Returns
    ///
    /// * `Result<(), AgentError>` - Returns `Ok(())` if the path is valid,
    ///   otherwise returns an `AgentError` with a descriptive error message.
    ///
    /// # Errors
    ///
    /// Returns an `AgentError::ConfigError` with a descriptive message if:
    /// * The path is empty or contains only whitespace
    /// * The path doesn't start with '/'
    /// * The path contains control characters ('\0', '\n', '\r')
    /// * The path contains query parameters ('?') or fragments ('#')
    /// * The path contains nested braces
    /// * The path has unmatched braces
    /// * The path contains empty parameter names
    /// * The path contains duplicate parameter names
    /// * The path contains invalid characters in parameter names
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(validate_rest_path("/api/users").is_ok());
    /// assert!(validate_rest_path("/api/users/{id}").is_ok());
    /// assert!(validate_rest_path("api/users").is_err()); // Missing leading slash
    /// assert!(validate_rest_path("/api/users/{id}/{id}").is_err()); // Duplicate parameter
    /// assert!(validate_rest_path("/api/users/{id?}").is_err()); // Invalid parameter name
    /// ```
    pub fn validate_rest_path(rest_path: &str) -> Result<(), AgentError> {
        if rest_path.trim().is_empty() {
            return Err(AgentError::ConfigError("Route path cannot be empty".to_string()));
        }

        if !rest_path.starts_with('/') {
            return Err(AgentError::ConfigError(format!("Route path must start with '/': {}", rest_path)));
        }

        if rest_path.contains('\0') || rest_path.contains('\n') || rest_path.contains('\r') {
            return Err(AgentError::ConfigError(format!(
                "Route path contains invalid control characters: {}",
                rest_path
            )));
        }

        if rest_path.contains('?') || rest_path.contains('#') {
            return Err(AgentError::ConfigError(format!(
                "Route path should not contain query parameters or fragments: {}",
                rest_path
            )));
        }

        let mut brace_count = 0;
        let mut param_names = Vec::new();
        let mut current_param = String::new();
        let mut in_param = false;

        for c in rest_path.chars() {
            match c {
                '{' => {
                    brace_count += 1;
                    if brace_count > 1 {
                        return Err(AgentError::ConfigError(format!(
                            "Nested braces are not allowed in path: {}",
                            rest_path
                        )));
                    }
                    in_param = true;
                    current_param.clear();
                },
                '}' => {
                    if !in_param {
                        return Err(AgentError::ConfigError(format!("Unmatched closing brace in path: {}", rest_path)));
                    }
                    brace_count -= 1;
                    in_param = false;

                    if current_param.is_empty() {
                        return Err(AgentError::ConfigError(format!("Empty parameter name in path: {}", rest_path)));
                    }

                    if param_names.contains(&current_param) {
                        return Err(AgentError::ConfigError(format!(
                            "Duplicate parameter name '{}' in path: {}",
                            current_param, rest_path
                        )));
                    }

                    param_names.push(current_param.clone());
                },
                _ if in_param => {
                    if !c.is_alphanumeric() && c != '_' {
                        return Err(AgentError::ConfigError(format!(
                            "Invalid character '{}' in parameter name, path: {}",
                            c, rest_path
                        )));
                    }
                    current_param.push(c);
                },
                _ => {},
            }
        }

        if brace_count != 0 {
            return Err(AgentError::ConfigError(format!("Unmatched braces in path: {}", rest_path)));
        }

        Ok(())
    }
}
