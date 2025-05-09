use key_management::key_manager::error::KeyManagerError;
use mockall::predicate::*;
use mockall::*;
use serde_json::json;
use token_management::token_manager;
use token_manager::TokenManager;
use tokio;


mock! {
    pub CryptoImpl {
        async fn get_public_key(&self, key_type: &str, version: Option<String>) -> Result<key_management::api::KeyInfoResp, KeyManagerError>;
    }
}

#[tokio::test]
async fn test_generate_token_uninitialized() {
    let mut json_body = json!({});
    let result = TokenManager::generate_token(&mut json_body).await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Generate token failed: Key is not initialized".to_string()
    );
}

#[tokio::test]
async fn test_verify_token_No_key_found() {
    let mut mock = MockCryptoImpl::new();
    mock.expect_get_public_key()
        .returning(|_, _| Err(KeyManagerError::new("No key found")));

    let result = TokenManager::verify_token("test_token").await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Verify token failed: No key found, version: ".to_string()
    );
}