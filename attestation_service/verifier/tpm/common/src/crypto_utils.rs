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

pub struct CryptoVerifier;

impl CryptoVerifier {
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

    pub fn verify_rsa_signature(
        data: &[u8],
        signature: &[u8], 
        hash_alg: MessageDigest,
        public_key: &PKey<Public>
    ) -> Result<(), PluginError> {
        let mut verifier = Verifier::new(hash_alg, public_key)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to create verifier: {}", e)
            ))?;
        
        verifier.update(data)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to update verifier: {}", e)
            ))?;
        
        let result = verifier.verify(signature)
            .map_err(|e| PluginError::InternalError(
                format!("RSA signature verification failed with error: {}", e)
            ))?;
            
        if !result {
            return Err(PluginError::InputError(
                "RSA signature verification failed - signature does not match data".to_string()
            ));
        }
        
        Ok(())
    }

    pub fn verify_rsapss_signature(
        data: &[u8],
        signature: &[u8],
        hash_alg: MessageDigest,
        public_key: &PKey<Public>
    ) -> Result<(), PluginError> {
        let mut verifier = Verifier::new(hash_alg, public_key)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to create verifier: {}", e)
            ))?;
        
        verifier.set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to set PSS padding: {}", e)
            ))?;
        
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to set salt length: {}", e)
            ))?;
        
        verifier.update(data)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to update verifier: {}", e)
            ))?;
        
        let result = verifier.verify(signature)
            .map_err(|e| PluginError::InternalError(
                format!("RSA-PSS signature verification failed: {}", e)
            ))?;
            
        if !result {
            return Err(PluginError::InputError(
                "RSA-PSS signature verification failed - signature does not match data".to_string()
            ));
        }
        
        Ok(())
    }

    pub fn verify_ecdsa_signature(
        data: &[u8],
        signature: &[u8],
        hash_alg: MessageDigest,
        public_key: &PKey<Public>
    ) -> Result<(), PluginError> {
        let mut verifier = Verifier::new(hash_alg, public_key)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to create verifier: {}", e)
            ))?;
        
        verifier.update(data)
            .map_err(|e| PluginError::InternalError(
                format!("Failed to update verifier: {}", e)
            ))?;
        
        let result = verifier.verify(signature)
            .map_err(|e| PluginError::InternalError(
                format!("ECDSA signature verification failed with error: {}", e)
            ))?;
            
        if !result {
            return Err(PluginError::InputError(
                "ECDSA signature verification failed - signature does not match data".to_string()
            ));
        }
        
        Ok(())
    }
}
