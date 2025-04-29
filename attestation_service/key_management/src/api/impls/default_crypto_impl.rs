use common_log::info;
use crate::api::crypto_operations::CryptoOperations;
use crate::api::model::KeyInfoResp;
use crate::api::model::SignResponse;
use crate::api::model::VerifyAndUpdateResponse;
use crate::api::model::VerifyAndUpdateResponseBuilder;
use crate::config::{ConfigLoader, YamlConfigLoader};
use crate::key_manager::algorithm::factory::algorithm_factory::create_algorithm;
use crate::key_manager::cache::store::KeyStore;
use crate::key_manager::error::KeyManagerError;
use crate::key_manager::model::VerifyAndUpdateParam;
use crate::key_manager::model::Version;

#[derive(Debug)]
pub struct DefaultCryptoImpl;

#[async_trait::async_trait]
impl CryptoOperations for DefaultCryptoImpl {
    async fn is_require_sign(&self) -> Result<bool, KeyManagerError> {
        let yaml_loader = YamlConfigLoader;
        let config = yaml_loader.load_config();
        if let Some(config) = config {
            Ok(config.is_require_sign())
        } else {
            Ok(false)
        }
    }

    async fn sign(&self, data: &Vec<u8>, key_type: &str) -> Result<SignResponse, KeyManagerError> {
        let key_store = KeyStore::global();
        let version = key_store.get_latest_version().unwrap();
        let key_pair = match key_store.get(key_type, version) {
            Some(key_pair) => key_pair,
            None => return Err(KeyManagerError::new(format!("No key found, version: {}", &version))),
        };
        let algorithm = create_algorithm(key_pair.algorithm.as_str()).unwrap();

        let result = algorithm
            .sign(&key_pair.private_key(), data.clone())
            .unwrap();
        Ok(SignResponse::new(result, version.to_string()))
    }

    async fn verify_and_update(
        &self,
        param: &VerifyAndUpdateParam,
    ) -> Result<VerifyAndUpdateResponse, KeyManagerError> {
        let version = param.key_version.as_str();
        let key_store = KeyStore::global();
        let max_version = key_store.get_latest_version().unwrap();
        let verification_result = Self::verify(
            self,
            param.key_type.as_str(),
            Some(version),
            param.data.clone(),
            param.signature.clone(),
        )
        .await;
        let is_verification_success = match verification_result {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => return Err(KeyManagerError::new(e.to_string())),
        };
        if !is_verification_success {
            return Err(KeyManagerError::new(&format!(
                "verify failed, version: {}",
                &version
            )));
        }
        let need_update = Version::new(version) < Version::new(max_version);
        if need_update {
            let signature_resp = Self::sign(self, &param.data, param.key_type.as_str())
                .await
                .map_err(|e| {
                    KeyManagerError::new(&format!(
                        "sign failed, versoin: {}, err info: {}",
                        &version, &e
                    ))
                })?;
            return Ok(
                VerifyAndUpdateResponseBuilder::new(is_verification_success, need_update)
                    .key_version(max_version.to_string())
                    .signature(signature_resp.signature)
                    .build(),
            );
        }
        Ok(VerifyAndUpdateResponseBuilder::new(is_verification_success, need_update).build())
    }

    async fn get_public_key(
        &self,
        key_type: &str,
        version: Option<&str>,
    ) -> Result<KeyInfoResp, KeyManagerError> {
        let key_store = KeyStore::global();
        // Bind temporary values to variables to extend their lifespan
        let latest_version = key_store.get_latest_version().unwrap();
        let version = version.unwrap_or(&latest_version);
        let key_pair = match key_store.get(key_type, version) {
            Some(key_pair) => key_pair,
            None => return Err(KeyManagerError::new(format!("No key found, version: {}", &version))),
        };
        let public_key = key_pair.public_key().public_key_to_pem().unwrap();
        Ok(KeyInfoResp::new(
            public_key.clone(),
            version.to_string(),
            key_pair.algorithm.clone(),
        ))
    }

    async fn get_private_key(
        &self,
        key_type: &str,
        version: Option<&str>,
    ) -> Result<KeyInfoResp, KeyManagerError> {
        let key_store = KeyStore::global();
        // Bind temporary values to variables to extend their lifespan
        let latest_version = key_store.get_latest_version().unwrap();
        let version = version.unwrap_or(&latest_version);
        let key_pair = match key_store.get(key_type, version) {
            Some(key_pair) => key_pair,
            None => return Err(KeyManagerError::new(format!("No key found, version: {}", &version))),
        };
        let private_key = key_pair.private_key().private_key_to_pem_pkcs8().unwrap();
        Ok(KeyInfoResp::new(
            private_key.clone(),
            version.to_string(),
            key_pair.algorithm.clone(),
        ))
    }

    async fn verify(
        &self,
        key_type: &str,
        key_version: Option<&str>,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, KeyManagerError> {
        let key_store = KeyStore::global();
        let max_version = key_store.get_latest_version().unwrap();
        let key_version = key_version.unwrap_or(max_version);
        let key_pair = match key_store.get(key_type, key_version) {
            Some(key_pair) => key_pair,
            None => return Err(KeyManagerError::new(format!("No key found, version: {}", &key_version))),
        };
        info!("create algorithm");
        let algorithm = create_algorithm(key_pair.algorithm.as_str()).unwrap();
        info!("create algorithm success: {}", key_pair.algorithm.as_str());
        algorithm.verify(&key_pair.public_key(), data, signature)
    }
}

#[allow(warnings)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::cache::entity::key_pair::KeyPair;
    use once_cell::sync::OnceCell;
    use openssl::rsa::Rsa;
    use serial_test::serial;
    use tokio::io::AsyncWriteExt;

    // Helper function to generate test key pairs
    fn generate_key_pair(algorithm: &str) -> KeyPair {
        let rsa = Rsa::generate(2048).unwrap();
        KeyPair {
            cached_private: OnceCell::new(),
            cached_public: OnceCell::new(),
            private_bytes: rsa.private_key_to_pem().unwrap(),
            public_bytes: rsa.public_key_to_pem().unwrap(),
            algorithm: algorithm.to_string(),
        }
    }

    // Initialize test environment (reset KeyStore before each test)
    fn init_test_store() {
        let store = KeyStore::global();
        // Clear all versions of TSK type
        if let Some(versions) = store.inner.get("TSK") {
            versions.write().unwrap().clear();
        }

        unsafe {
            let store_ptr = store as *const KeyStore as *mut KeyStore;
            (*store_ptr).latest_version.take();
        }
    }

    #[tokio::test]
    #[serial] // Ensure serial execution
    async fn test_version_ordering() {
        init_test_store();
        let store = KeyStore::global();

        // Insert versions in random order
        store
            .insert("TSK", "v3", generate_key_pair("rsa 3072 pss"))
            .unwrap();
        store
            .insert("TSK", "v1", generate_key_pair("rsa 3072 pss"))
            .unwrap();
        store
            .insert("TSK", "v2", generate_key_pair("rsa 3072 pss"))
            .unwrap();

        assert_eq!(store.get_latest_version().unwrap(), "v3");
        init_test_store();
    }

    #[tokio::test]
    #[serial]
    async fn test_sign_flow() {
        init_test_store();
        let crypto = DefaultCryptoImpl;

        // Prepare test data
        let data = b"test_data".to_vec();

        // Insert key
        KeyStore::global()
            .insert("TSK", "v1", generate_key_pair("rsa 3072 pss"))
            .unwrap();

        // Normal signature
        let resp = crypto.sign(&data, "TSK").await.unwrap();
        assert_eq!(resp.key_version, "v1");
        assert!(!resp.signature.is_empty());
        init_test_store();
    }

    #[tokio::test]
    #[serial]
    async fn test_verify_and_update_flow() {
        init_test_store();
        let crypto = DefaultCryptoImpl;

        // Prepare multi-version environment
        KeyStore::global()
            .insert("TSK", "v1", generate_key_pair("rsa 3072 pss"))
            .unwrap();
        KeyStore::global()
            .insert("TSK", "v2", generate_key_pair("rsa 3072 pss"))
            .unwrap();

        // Sign with v2
        let data = b"important".to_vec();
        let v2_sig = crypto.sign(&data, "TSK").await.unwrap().signature;

        // Construct verification parameters
        let param = VerifyAndUpdateParam {
            key_type: "TSK".to_string(),
            key_version: "v2".to_string(),
            data: data.clone(),
            signature: v2_sig,
        };
        unsafe {
            let store_ptr = KeyStore::global() as *const KeyStore as *mut KeyStore;
            (*store_ptr).latest_version.take();
        }
        KeyStore::global()
            .insert("TSK", "v3", generate_key_pair("rsa 3072 pss"))
            .unwrap();

        // Verify and update
        let resp = crypto.verify_and_update(&param).await.unwrap();
        assert!(resp.verification_success);
        assert!(resp.need_update);
        assert_eq!(resp.key_version.unwrap(), "v3");

        // Verify new signature validity
        let verify = crypto
            .verify("TSK", Some("v3"), data, resp.signature.unwrap())
            .await
            .unwrap();
        assert!(verify);
        init_test_store();
    }

    #[tokio::test]
    #[serial]
    async fn test_key_pem_export() {
        init_test_store();
        let crypto = DefaultCryptoImpl;

        // Insert test key
        KeyStore::global()
            .insert("TSK", "v1", generate_key_pair("rsa 3072 pss"))
            .unwrap();

        // Verify public key format
        let pub_resp = crypto.get_public_key("TSK", Some("v1")).await.unwrap();

        // Verify private key format
        let priv_resp = crypto.get_private_key("TSK", Some("v1")).await.unwrap();
        init_test_store();
    }
}
