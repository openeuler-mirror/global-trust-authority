use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;
use common_log::{error, info};
use crate::policy_error::policy_error::PolicyError;
use config_manager::types::context::CONFIG;

pub struct ExportPolicyHandler;

impl ExportPolicyHandler {

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

    pub fn read_policy_file(policy_file_path: &str) -> Result<String, PolicyError> {
        match fs::read_to_string(policy_file_path) {
            Ok(content) => Ok(content),
            Err(e) => {
                error!("Failed to read policy file {}: {}", policy_file_path, e);
                Err(PolicyError::PolicyNotFoundError(format!("Failed to read policy file: {}", e)))
            }
        }
    }

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