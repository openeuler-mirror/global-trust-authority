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

//! Quote verifier, verify quote data and signature.
//! nonce is optional, if nonce is not provided, it will not be verified.
//! # Examples
//! See the `verify` method for an example of how to use the QuoteVerifier struct.
use openssl::pkey::{PKey, Public};
use serde::{Serialize, Deserialize};
use openssl::ecdsa::EcdsaSig;
use openssl::bn::BigNum;
use plugin_manager::PluginError;
use crate::structure::{TpmsAttest, TpmtSignature, SignatureData, Tpm2SignatureAlgID, AlgorithmId};
use crate::crypto_utils::{CryptoVerifier, SignatureType};

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteVerifier {
    quote_data: TpmsAttest,
    signature: TpmtSignature,
}

const MAX_NONCE_SIZE: usize = 32;

impl QuoteVerifier {
    /// Create QuoteVerifier from raw Quote and signature data
    ///
    /// # Arguments
    /// * `quote` - Raw quote data bytes, base64 encoded
    /// * `signature` - Signature data bytes, base64 encoded
    ///
    /// # Returns
    /// * `Result<Self, PluginError>` - QuoteVerifier instance or error
    /// # Example
    /// ```ignore
    /// let quote = "base64 encoded quote data";
    /// let signature = "base64 encoded signature data";
    /// let quote_verifier = QuoteVerifier::new(&quote, &signature).unwrap();
    /// ```
    /// 
    /// # Error
    /// 
    /// * `PluginError::InputError` - Failed to parse Quote or signature data
    pub fn new(quote: &Vec<u8>, signature: &Vec<u8>) -> Result<Self, PluginError> {
        let tpm_signature = TpmtSignature::deserialize(signature)
            .map_err(|e| PluginError::InputError(format!("Failed to parse signature data: {}", e)))?;
        
        let quote_data = TpmsAttest::deserialize(quote)
            .map_err(|e| PluginError::InputError(format!("Failed to parse Quote data: {}", e)))?;
        
        Ok(Self {
            quote_data,
            signature: tpm_signature
        })
    }

    /// Verify the Quote data and signature
    ///
    /// # Arguments
    /// * `quote_data` - Raw quote data bytes to verify
    /// * `public_ak` - Public attestation key for signature verification
    /// * `nonce` - Optional nonce value to verify against Quote
    ///
    /// # Returns
    /// * `Result<(), PluginError>` - Success or error
    /// # Example
    /// ```ignore
    /// let quote_data = "base64 encoded quote data";
    /// let signature = "base64 encoded signature data";
    /// let public_ak = "base64 encoded public attestation key";
    /// let nonce = Some("base64 encoded nonce data");
    /// let result = quote_verifier.verify(&quote_data, &public_ak, nonce).unwrap();
    /// ```
    /// 
    /// # Error
    /// 
    /// * `PluginError::InputError` - Failed to verify signature or Quote data
    pub fn verify(
        &self,
        quote_data: &Vec<u8>,
        public_ak: &PKey<Public>,
        nonce: Option<&[u8]>
    ) -> Result<(), PluginError> {
        self.verify_signature(quote_data, public_ak)?;
        self.verify_quote_data(nonce)?;
        
        Ok(())
    }

    /// Verify the signature of the Quote data
    ///
    /// # Arguments
    /// 
    /// * `quote_data` - Raw quote data bytes to verify
    /// * `public_ak` - Public attestation key for signature verification
    /// 
    /// # Returns
    /// 
    /// * `Result<(), PluginError>` - Success or error
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - Failed to verify signature
    pub fn verify_signature(&self, quote_data: &Vec<u8>, public_ak: &PKey<Public>) -> Result<(), PluginError> {
        // 1. Get signature type
        let sig_type = self.get_signature_type()?;

        // 2. Get hash algorithm and signature data based on signature data type
        let (hash_alg, signature_data) = match &self.signature.signature {
            SignatureData::RsaSignature(rsa) => {
                let hash_alg = self.get_hash_algorithm_from_signature(&rsa.hash)?;
                (hash_alg, rsa.signature.clone())
            },
            SignatureData::EccSignature(ecc) => {
                let hash_alg = self.get_hash_algorithm_from_signature(&ecc.hash)?;
                let der_signature = self.convert_ecdsa_to_der(&ecc.signature_r, &ecc.signature_s)
                    .map_err(|e| PluginError::InputError(format!("Failed to convert ECDSA signature to DER format: {}", e)))?;
                (hash_alg, der_signature)
            }
        };

        // 3. Execute signature verification
        CryptoVerifier::verify_signature(quote_data, &signature_data, hash_alg, public_ak, sig_type)
            .map_err(|e| PluginError::InputError(format!("{:?} signature verification failed: {}", sig_type, e)))?;

        Ok(())
    }

    /// Get corresponding SignatureType from signature algorithm ID
    fn get_signature_type(&self) -> Result<SignatureType, PluginError> {
        match self.signature.sig_alg {
            Tpm2SignatureAlgID::Rsa | Tpm2SignatureAlgID::RsaSsa => Ok(SignatureType::Rsa),
            Tpm2SignatureAlgID::RsaPss => Ok(SignatureType::RsaPss),
            Tpm2SignatureAlgID::Ecdsa | Tpm2SignatureAlgID::Ecdaa => Ok(SignatureType::Ecdsa),
            Tpm2SignatureAlgID::Sm2 => Ok(SignatureType::Sm2),
            _ => Err(PluginError::InputError(format!("Unsupported signature algorithm: {:?}", self.signature.sig_alg))),
        }
    }

    /// Get OpenSSL MessageDigest from algorithm ID
    fn get_hash_algorithm_from_signature(&self, alg: &AlgorithmId) -> Result<openssl::hash::MessageDigest, PluginError> {
        CryptoVerifier::algorithm_to_message_digest(alg)
            .map_err(|e| PluginError::InputError(format!("Unsupported hash algorithm: {}", e)))
    }

    fn convert_ecdsa_to_der(&self, r: &[u8], s: &[u8]) -> Result<Vec<u8>, &'static str> {
        let r_bn = BigNum::from_slice(r).map_err(|_| "Failed to create BigNum from r value")?;
        let s_bn = BigNum::from_slice(s).map_err(|_| "Failed to create BigNum from s value")?;
        
        let sig = EcdsaSig::from_private_components(r_bn, s_bn)
            .map_err(|_| "Failed to create ECDSA signature from r and s components")?;
        
        let der = sig.to_der().map_err(|_| "Failed to convert ECDSA signature to DER format")?;
        
        Ok(der)
    }

    /// Verify the Quote data
    ///
    /// # Arguments
    /// 
    /// * `nonce` - Optional nonce value to verify against Quote
    /// 
    /// # Returns
    /// 
    /// * `Result<(), PluginError>` - Success or error
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - Failed to verify Quote data
    pub fn verify_quote_data(&self, nonce: Option<&[u8]>) -> Result<(), PluginError> {
        // 1. Verify magic value
        if self.quote_data.magic != crate::structure::TPM2_GENERATED_VALUE {
            return Err(PluginError::InputError(
                format!("Invalid TPM magic value: 0x{:08X}", self.quote_data.magic)
            ));
        }

        // 2. Verify nonce (if provided)
        if let Some(nonce_data) = nonce {
            if self.quote_data.extra_data != nonce_data {
                return Err(PluginError::InputError("Nonce in Quote does not match provided nonce".to_string()));
            }
        }

        // 3. Get PCR digest information
        let pcr_digest = &self.quote_data.attested.pcr_digest;
        if pcr_digest.is_empty() {
            return Err(PluginError::InputError("PCR digest in Quote is empty".to_string()));
        }
        
        // 4. Verify PCR selection information
        if self.quote_data.attested.pcr_select.is_empty() {
            return Err(PluginError::InputError("PCR selection in Quote is empty".to_string()));
        }
        
        // 5. Check if hash algorithm is supported
        for selection in &self.quote_data.attested.pcr_select {
            if selection.hash_alg == AlgorithmId::Unknown {
                return Err(PluginError::InputError("PCR selection contains unsupported hash algorithm".to_string()));
            }
        }
        
        Ok(())
    }

    /// Get the hash algorithm used in the Quote
    ///
    /// # Returns
    /// * `AlgorithmId` - Hash algorithm identifier
    /// 
    /// # Panics
    /// 
    /// * If the PCR selection is empty
    pub fn get_hash_algorithm(&self) -> AlgorithmId {
        self.quote_data.attested.pcr_select.first().unwrap().hash_alg
    }

    /// Get the PCR digest from the Quote
    ///
    /// # Returns
    /// * `&[u8]` - PCR digest bytes
    pub fn get_pcr_digest(&self) -> &[u8] {
        &self.quote_data.attested.pcr_digest
    }
}
