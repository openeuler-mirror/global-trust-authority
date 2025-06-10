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

use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;
use common_log::{error, info};
use crate::error::policy_error::PolicyError;
use config_manager::types::context::CONFIG;

pub struct ExportPolicyHandler;

impl ExportPolicyHandler {

    /// Retrieves the export policy content from the cache based on attester type.
    ///
    /// # Arguments
    /// * `attester_type` - The type of attester to look up in the cache.
    /// * `cache_lock` - A read-write lock protecting the cache HashMap.
    ///
    /// # Returns
    /// * `Result<Option<String>, PolicyError>` - Returns `Ok(Some(content))` if found in cache,
    ///   `Ok(None)` if not found, or `Err(PolicyError::InternalError)` if acquiring the read lock fails.
    /// 
    /// #Error
    /// * `PolicyError::InternalError` - If acquiring the read lock fails.
    /// Failed to acquire read lock on export policy cache: Failed to acquire read lock: lock poisoned
    pub fn get_policy_from_cache(attester_type: &str, cache_lock: &RwLock<HashMap<String, String>>) -> Result<Option<String>, PolicyError> {
        let cache = cache_lock.read().map_err(|e| {
            error!("Failed to acquire read lock on export policy cache: {}", e);
            PolicyError::InternalError(format!("Failed to acquire read lock: {}", e))
        })?;
        
        if let Some(content) = cache.get(attester_type) {
            info!("Found cached export policy for attester_type: {}", attester_type);
            return Ok(Some(content.clone()));
        }
        
        Ok(None)
    }

    /// Gets the file path for the export policy based on attester type from the configuration.
    ///
    /// # Arguments
    /// * `attester_type` - The type of attester to find the policy file path for.
    ///
    /// # Returns
    /// * `Result<String, PolicyError>` - Returns `Ok(file_path)` if found in config,
    ///   `Err(PolicyError::InternalError)` if getting config instance fails,
    ///   or `Err(PolicyError::PolicyNotFoundError)` if no matching file is found in config.
    /// 
    /// #Error
    /// * `PolicyError::InternalError` - If getting config instance fails.  
    /// * `PolicyError::PolicyNotFoundError` - If no matching file is found in config.
    pub fn get_policy_file_path(attester_type: &str) -> Result<String, PolicyError> {
        let config = CONFIG.get_instance().map_err(|e| {
            error!("Failed to get config instance: {}", e);
            PolicyError::InternalError(format!("Failed to get config instance: {}", e))
        })?;

        for policy_file in &config.attestation_service.policy.export_policy_file {
            if policy_file.name == attester_type {
                return Ok(policy_file.path.clone());
            }
        }
        
        error!("No export policy file found for attester_type: {}", attester_type);
        Err(PolicyError::PolicyNotFoundError(format!("No policy file found for: {}", attester_type)))
    }

    /// Reads the content of a policy file from the given path.
    ///
    /// # Arguments
    /// * `policy_file_path` - The path to the policy file.
    ///
    /// # Returns
    /// * `Result<String, PolicyError>` - Returns `Ok(content)` if the file is read successfully,
    ///   or `Err(PolicyError::PolicyNotFoundError)` if reading the file fails.
    pub fn read_policy_file(policy_file_path: &str) -> Result<String, PolicyError> {
        match fs::read_to_string(policy_file_path) {
            Ok(content) => Ok(content),
            Err(e) => {
                error!("Failed to read policy file {}: {}", policy_file_path, e);
                Err(PolicyError::PolicyNotFoundError(format!("Failed to read policy file: {}", e)))
            }
        }
    }

    /// Caches the export policy content for a given attester type.
    ///
    /// # Arguments
    /// * `attester_type` - The type of attester to cache the policy for.
    /// * `content` - The policy content to cache.
    /// * `cache_lock` - A read-write lock protecting the cache HashMap.
    ///
    /// # Returns
    /// * `Result<(), PolicyError>` - Returns `Ok(())` if caching is successful,
    ///   or `Err(PolicyError::InternalError)` if acquiring the write lock fails.
    pub fn cache_policy(attester_type: &str, content: String, cache_lock: &RwLock<HashMap<String, String>>) -> Result<(), PolicyError> {
        let mut cache = cache_lock.write().map_err(|e| {
            error!("Failed to acquire write lock on export policy cache: {}", e);
            PolicyError::InternalError(format!("Failed to acquire write lock: {}", e))
        })?;
        
        cache.insert(attester_type.to_string(), content);
        info!("Cached export policy for attester_type: {}", attester_type);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_get_policy_from_cache() {
        let cache_lock = RwLock::new(HashMap::new());
        let mut cache = cache_lock.write().unwrap();
        cache.insert("test_type".to_string(), "test_content".to_string());
        drop(cache);

        let result = ExportPolicyHandler::get_policy_from_cache("test_type", &cache_lock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("test_content".to_string()));

        let result = ExportPolicyHandler::get_policy_from_cache("non_existent", &cache_lock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_read_policy_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_policy.txt");
        let test_content = "test policy content";

        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        let result = ExportPolicyHandler::read_policy_file(file_path.to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_content);

        let result = ExportPolicyHandler::read_policy_file("non_existent_file");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::PolicyNotFoundError(_)));
    }

    #[test]
    fn test_cache_policy() {
        let cache_lock = RwLock::new(HashMap::new());
        let result = ExportPolicyHandler::cache_policy(
            "test_type",
            "test_content".to_string(),
            &cache_lock
        );
        assert!(result.is_ok());

        let cache = cache_lock.read().unwrap();
        assert_eq!(cache.get("test_type").unwrap(), "test_content");
    }
}