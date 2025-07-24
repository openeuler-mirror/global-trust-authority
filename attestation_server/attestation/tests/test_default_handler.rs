use serde_json::json;
use attestation::handler::default_handler::DefaultHandler;

#[test]
fn test_get_aggregate_nonce_bytes() {
    // Test case 1: Both nonce and attester_data are None
    let result = DefaultHandler::get_aggregate_nonce_bytes(&None, &None);
    assert!(result.is_none(), "Expected None when both inputs are None");

    // Test case 2: Only nonce is Some
    let nonce = Some(b"test_nonce".to_vec());
    let result = DefaultHandler::get_aggregate_nonce_bytes(&nonce, &None).unwrap();
    // The exact hash value depends on the implementation, but we can check the length
    // SHA-256 produces 32 bytes
    assert_eq!(result.len(), 32, "Expected 32 bytes for SHA-256 hash");

    // Test case 3: Only attester_data is Some
    let attester_data = Some(json!({"key": "value"}));
    let result = DefaultHandler::get_aggregate_nonce_bytes(&None, &attester_data).unwrap();
    assert_eq!(result.len(), 32, "Expected 32 bytes for SHA-256 hash");

    // Test case 4: Both nonce and attester_data are Some
    let nonce = Some(b"test_nonce".to_vec());
    let attester_data = Some(json!({"key": "value"}));
    let result1 = DefaultHandler::get_aggregate_nonce_bytes(&nonce, &attester_data).unwrap();
    assert_eq!(result1.len(), 32, "Expected 32 bytes for SHA-256 hash");

    // Test case 5: Same inputs should produce same output
    let result2 = DefaultHandler::get_aggregate_nonce_bytes(&nonce, &attester_data).unwrap();
    assert_eq!(result1, result2, "Same inputs should produce same output");

    // Test case 6: Different nonce produces different output
    let different_nonce = Some(b"different_nonce".to_vec());
    let result3 = DefaultHandler::get_aggregate_nonce_bytes(&different_nonce, &attester_data).unwrap();
    assert_ne!(result1, result3, "Different nonce should produce different output");

    // Test case 7: Different attester_data produces different output
    let different_data = Some(json!({"different_key": "different_value"}));
    let result4 = DefaultHandler::get_aggregate_nonce_bytes(&nonce, &different_data).unwrap();
    assert_ne!(result1, result4, "Different attester_data should produce different output");
}