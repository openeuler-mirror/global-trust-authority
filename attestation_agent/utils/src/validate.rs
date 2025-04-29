pub mod validate_utils {
    use std::fs;
    use std::path::Path;
    use validator::ValidationError;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use regex::Regex;
    use crate::agent_error::AgentError;

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
        if let Err(_) = fs::metadata(path_obj).and_then(|metadata| {
            if metadata.permissions().readonly() {
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "File is not readable"))
            } else {
                Ok(())
            }
        }) {
            return Err(ValidationError::new("Cannot read file"));
        }

        Ok(())
    }

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
        let hostname_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
        if hostname_regex.is_match(address) {
            return Ok(());
        }

        Err(ValidationError::new("Invalid bind address. Must be a valid IPv4, IPv6 address or hostname"))
    }

    pub fn validate_rest_path(rest_path: &str) -> Result<(), AgentError> {
        if rest_path.trim().is_empty() {
            return Err(AgentError::ConfigError("Route path cannot be empty".to_string()));
        }

        if !rest_path.starts_with('/') {
            return Err(AgentError::ConfigError(format!("Route path must start with '/': {}", rest_path)));
        }

        if rest_path.contains('\0') || rest_path.contains('\n') || rest_path.contains('\r') {
            return Err(AgentError::ConfigError(format!("Route path contains invalid control characters: {}", rest_path)));
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

