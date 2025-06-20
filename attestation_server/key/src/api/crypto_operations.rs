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

use crate::api::model::KeyInfoResp;
use crate::api::model::SignResponse;
use crate::api::model::VerifyAndUpdateResponse;
use crate::key_manager::error::KeyManagerError;
use crate::key_manager::model::VerifyAndUpdateParam;
use async_trait::async_trait;

/**
 * Cryptographic Operations Interface
 */
#[async_trait]
pub trait CryptoOperations {
    /**
     * Check if key rotation is required
     *
     * @return Whether key rotation is needed
     * */
    async fn is_require_sign(&self) -> Result<bool, KeyManagerError>;
    /**
     * Sign data
     *
     * @param data Data to be signed
     * @return Signature value
     * */
    async fn sign(&self, data: &Vec<u8>, key_type: &str) -> Result<SignResponse, KeyManagerError>;

    /**
     * Verify signature
     *
     * @param data Data to be verified
     * @param signature Signature value
     * Verify signature and update key
     *
     * @param key_type Key type
     * @param key_version Key version
     * @param data Data to be verified
     * @param signature Signature value
     * @return Result of signature verification and key update
     * */
    async fn verify_and_update(
        &self,
        param: &VerifyAndUpdateParam,
    ) -> Result<VerifyAndUpdateResponse, KeyManagerError>;

    /**
     * Get public key
     *
     * @param version Key version
     * @return Public key
     * */
    async fn get_public_key(
        &self,
        key_type: &str,
        version: Option<&str>,
    ) -> Result<KeyInfoResp, KeyManagerError>;

    /**
     * Get private key
     *
     * @param version Key version
     * @return Private key
     * */
    async fn get_private_key(
        &self,
        key_type: &str,
        version: Option<&str>,
    ) -> Result<KeyInfoResp, KeyManagerError>;

    /**
     * Verify signature
     *
     * @param data Data to be verified
     * @param signature Signature value
     * @param key_type Key type
     * @return Result of signature verification
     * */
    async fn verify(
        &self,
        key_type: &str,
        key_version: Option<&str>,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, KeyManagerError>;
}
