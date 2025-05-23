use crate::key_manager::algorithm::factory::algorithm_factory::KeyAlgorithm;
use crate::key_manager::error::KeyManagerError;
use crate::register_algorithm;
use anyhow::anyhow;
use anyhow::Result;
use once_cell::sync::OnceCell;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use common_log::{error, info};
use crate::key_manager::cache::entity::key_pair::KeyPair;
use crate::key_manager::model::PrivateKey;

/// RSA algorithm implementation
#[derive(Debug)]
pub struct RsaAlgorithm {
    name: String,
    _bits: u32,
    padding: String,
}

impl KeyAlgorithm for RsaAlgorithm {
    fn derive_public(&self, private_key: &PrivateKey) -> Result<KeyPair, KeyManagerError> {
        info!("RsaAlgorithm: from private key to public key");
        // Trying to load a private key

        let private_pkey = PKey::private_key_from_pem(private_key.as_bytes())
            .map_err(|e| KeyManagerError::new(format!("load private key failed: {}", e)))?;
        info!("RsaAlgorithm: load private key success");

        // extracting the public key
        let pub_key = match self.padding.as_str() {
            "pss" => {
                info!("use PSS padding to derive public key");
                let mut signer = openssl::sign::Signer::new_without_digest(&private_pkey).map_err(|e| {
                    error!("create signer failed: {}", e);
                    KeyManagerError::new(format!("create signer failed: {}", e))
                })?;

                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;
                signer.set_rsa_pss_saltlen(RsaPssSaltlen::MAXIMUM_LENGTH)?;

                private_pkey.public_key_to_pem().map_err(|e| {
                    error!("public key der encode failed: {}", e);
                    KeyManagerError::new(format!("public key der encode failed: {}", e))
                })?
            }
            _ => {
                info!("use traditional RSA padding to derive public key");
                let rsa = private_pkey.rsa().map_err(|e| {
                    error!("PKey to RSA failed: {}", e);
                    KeyManagerError::new(format!("PKey to RSA failed: {}", e))
                })?;
                rsa.public_key_to_der().map_err(|e| {
                    error!("public key der encode failed: {}", e);
                    KeyManagerError::new(format!("public key der encode failed: {}", e))
                })?
            }
        };
        info!("RsaAlgorithm: public key der encode success");
        Ok(KeyPair {
            cached_private: OnceCell::new(),
            cached_public: OnceCell::new(),
            private_bytes: private_pkey.private_key_to_pem_pkcs8()?,
            public_bytes: pub_key,
            algorithm: self.name.clone(),
        })
    }

    fn sign(&self, private_key: &PKey<Private>, data: Vec<u8>) -> Result<Vec<u8>, KeyManagerError> {
        // creating a signer
        let mut signer = Signer::new_without_digest(private_key)?;
        if self.padding == "pss" {
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        }

        // signature data
        Ok(signer.sign_oneshot_to_vec(data.clone().as_slice())?)
    }

    fn verify(
        &self,
        public_key: &PKey<Public>,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, KeyManagerError> {
        info!("start verify data");
        let mut verifier = Verifier::new_without_digest(public_key)?;
        info!("get public key to verify");
        if self.padding == "pss" {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::MAXIMUM_LENGTH)?;
        }

        Ok(verifier.verify_oneshot(&signature, &data)?)
    }
}

// Auto-registration to global registry
register_algorithm!("rsa", |args: &[&str]| -> Result<Box<dyn KeyAlgorithm>> {
    // Resolve key length
    // The parameter resolution logic must support PSS
    let (bits, padding) = match args {
        [bits_str, "pss"] => (bits_str.parse()?, "pss".to_string()),
        [bits_str] => (bits_str.parse()?, "pkcs1".to_string()),
        _ => return Err(anyhow!("Invalid RSA parameters format")),
    };

    // Validity length
    if ![2048, 3072, 4096].contains(&bits) {
        return Err(anyhow!("SM2 algorithm does not accept parameters"));
    }

    Ok(Box::new(RsaAlgorithm {
        name: format!("rsa {} {}", bits, padding),
        _bits: bits,
        padding,
    }))
});