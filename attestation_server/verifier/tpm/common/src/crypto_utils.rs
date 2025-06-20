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

//! Crypto utilities for signature verification and hash operations
//!
//! This module provides helper functions for:
//! - Converting between algorithm IDs and OpenSSL message digests
//! - RSA signature verification
//! - Hash string parsing
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{Verifier, RsaPssSaltlen};
use plugin_manager::PluginError;
use crate::structure::AlgorithmId;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureType {
    Rsa,
    RsaPss,
    Ecdsa,
    Sm2,
}

pub struct CryptoVerifier;

impl CryptoVerifier {
    /// Converts an `AlgorithmId` enum value to an OpenSSL `MessageDigest`.
    ///
    /// # Arguments
    ///
    /// * `alg` - The `AlgorithmId` to convert.
    ///
    /// # Returns
    ///
    /// Returns `Ok(MessageDigest)` on success, or `Err(PluginError::InputError)`
    /// if the algorithm is not supported.
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the algorithm is not supported.
    pub fn algorithm_to_message_digest(alg: &AlgorithmId) -> Result<MessageDigest, PluginError> {
        match alg {
            AlgorithmId::Sha1 => Ok(MessageDigest::sha1()),
            AlgorithmId::Sha256 => Ok(MessageDigest::sha256()),
            AlgorithmId::Sha384 => Ok(MessageDigest::sha384()),
            AlgorithmId::Sha512 => Ok(MessageDigest::sha512()),
            AlgorithmId::Sm3 => Ok(MessageDigest::sm3()),
            _ => Err(PluginError::InputError(
                format!("Unsupported hash algorithm: {:?}", alg)
            ))
        }
    }

    /// Converts a hash algorithm name string to an OpenSSL `MessageDigest`.
    /// The string comparison is case-insensitive.
    ///
    /// # Arguments
    ///
    /// * `hash_str` - The string name of the hash algorithm (e.g., "sha256", "sm3").
    ///
    /// # Returns
    ///
    /// Returns `Ok(MessageDigest)` on success, or `Err(PluginError::InputError)`
    /// if the algorithm name is not recognized.
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the algorithm name is not recognized.    
    pub fn hash_str_to_message_digest(hash_str: &str) -> Result<MessageDigest, PluginError> {
        match hash_str.to_lowercase().as_str() {
            "sha1" => Ok(MessageDigest::sha1()),
            "sha256" => Ok(MessageDigest::sha256()),
            "sha384" => Ok(MessageDigest::sha384()),
            "sha512" => Ok(MessageDigest::sha512()),
            "sm3" => Ok(MessageDigest::sm3()),
            alg => Err(PluginError::InputError(
                format!("Unsupported hash algorithm: {}", alg)
            ))
        }
    }

    
    /// Converts a hash algorithm name string to its digest size in bytes.
    /// The string comparison is case-insensitive.
    ///
    /// # Arguments
    ///
    /// * `hash_str` - The string name of the hash algorithm (e.g., "sha256", "sm3").
    ///
    /// # Returns
    ///
    /// Returns `Ok(usize)` on success, or `Err(PluginError::InputError)`
    /// if the algorithm name is not recognized.
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InputError` - If the algorithm name is not recognized.    
    pub fn hash_str_to_digest_size(hash_str: &str) -> Result<usize, PluginError> {
        match hash_str.to_lowercase().as_str() {
            "sha1" => Ok(20_usize),
            "sha256" => Ok(32_usize),
            "sha384" => Ok(48_usize),
            "sha512" => Ok(64_usize),
            "sm3" => Ok(32_usize),
            alg => Err(PluginError::InputError(
                format!("Unsupported hash algorithm: {}", alg)
            ))
        }
    }


    /// Verifies a digital signature against the original data using a public key.
    /// Supports RSA, RSA-PSS, ECDSA, and SM2 signature types.
    ///
    /// # Arguments
    ///
    /// * `data` - The original data that was signed.
    /// * `signature` - The signature bytes to verify.
    /// * `hash_alg` - The message digest algorithm used for hashing the data before signing.
    /// * `public_key` - The public key corresponding to the private key used for signing.
    /// * `sig_type` - The type of signature (e.g., `SignatureType::Rsa`, `SignatureType::RsaPss`).
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the signature is valid.
    /// Returns `Err(PluginError::InternalError)` if an internal OpenSSL error occurs
    /// during verification setup or process.
    /// Returns `Err(PluginError::InputError)` if the signature does not match the data.
    /// 
    /// # Errors
    /// 
    /// * `PluginError::InternalError` - If an internal OpenSSL error occurs during verification setup or process.
    pub fn verify_signature(
        data: &[u8],
        signature: &[u8],
        hash_alg: MessageDigest,
        public_key: &PKey<Public>,
        sig_type: SignatureType,
    ) -> Result<(), PluginError> {
        let mut verifier = Verifier::new(hash_alg, public_key)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to create verifier: {}", e)
            ))?;

        // Set specific parameters based on signature type
        if sig_type == SignatureType::RsaPss {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)
                .map_err(|e| PluginError::InternalError(
                    format!("Failed to set PSS padding: {}", e)
                ))?;

            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(|e| PluginError::InternalError(
                    format!("Failed to set salt length: {}", e)
                ))?;
        }

        verifier.update(data)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to update verifier: {}", e)
            ))?;

        let result = verifier.verify(signature)
            .map_err(|e| PluginError::InternalError(
                format!("{:?} signature verification failed with error: {}", sig_type, e)
            ))?;

        if !result {
            return Err(PluginError::InputError(
                format!("{:?} signature verification failed - signature does not match data", sig_type)
            ));
        }

        Ok(())
    }
}
