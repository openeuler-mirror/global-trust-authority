use std::collections::HashMap;
use std::sync::RwLock;
use std::fs;
use tempfile::tempdir;

use policy::{
    policy_error::policy_error::PolicyError,
    handler::export_policy_handler::ExportPolicyHandler,
};


#[actix_web::test]
async fn test_get_export_policy_when_policy_file_exists_then_return_policy_content() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let policy_file_path = temp_dir.path().join("test-policy.yaml");

    let policy_content = "test: policy content";
    fs::write(&policy_file_path, policy_content).expect("Failed to write test policy file");

    let cache = RwLock::new(HashMap::new());

    let result = ExportPolicyHandler::read_policy_file(policy_file_path.to_str().unwrap());
    assert!(result.is_ok(), "Failed to read policy file: {:?}", result.err());
    assert_eq!(result.unwrap(), policy_content);

    let attester_type = "test-attester";
    let result = ExportPolicyHandler::cache_policy(attester_type, policy_content.to_string(), &cache);
    assert!(result.is_ok(), "Failed to cache policy: {:?}", result.err());

    let result = ExportPolicyHandler::get_policy_from_cache(attester_type, &cache);
    assert!(result.is_ok(), "Failed to get policy from cache: {:?}", result.err());
    assert_eq!(result.unwrap(), Some(policy_content.to_string()));

    let mut cache_map = cache.write().unwrap();
    cache_map.insert(attester_type.to_string(), policy_content.to_string());
    drop(cache_map);

    let result = ExportPolicyHandler::get_policy_from_cache(attester_type, &cache);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some(policy_content.to_string()));
}

#[actix_web::test]
async fn test_read_policy_file_when_file_not_exists_then_return_error() {
    let nonexistent_path = "/tmp/nonexistent-policy-file.yaml";
    let result = ExportPolicyHandler::read_policy_file(nonexistent_path);

    assert!(result.is_err());
    match result.err().unwrap() {
        PolicyError::PolicyNotFoundError(_) => {},
        err => panic!("Unexpected error type: {:?}", err),
    }
}