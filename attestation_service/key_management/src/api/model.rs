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

#[derive(Debug)]
pub struct VerifyAndUpdateResponse {
    pub verification_success: bool,
    pub need_update: bool,
    pub key_version: Option<String>,
    pub signature: Option<Vec<u8>>,
}

impl VerifyAndUpdateResponse {
    pub fn new(verification_success: bool, need_update: bool) -> Self {
        Self {
            verification_success,
            need_update,
            key_version: None,
            signature: None,
        }
    }

    pub fn key_version(mut self, key_version: String) -> Self {
        self.key_version = Some(key_version);
        self
    }

    pub fn signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
}

#[derive(Debug)]
pub struct VerifyAndUpdateResponseBuilder {
    verification_success: bool,
    need_update: bool,
    key_version: Option<String>,
    signature: Option<Vec<u8>>,
}

impl VerifyAndUpdateResponseBuilder {
    pub fn new(verification_success: bool, need_update: bool) -> Self {
        Self {
            verification_success,
            need_update,
            key_version: None,
            signature: None,
        }
    }

    pub fn key_version(mut self, key_version: String) -> Self {
        self.key_version = Some(key_version);
        self
    }

    pub fn signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    pub fn build(self) -> VerifyAndUpdateResponse {
        VerifyAndUpdateResponse {
            verification_success: self.verification_success,
            need_update: self.need_update,
            key_version: self.key_version,
            signature: self.signature,
        }
    }
}

#[derive(Debug)]
pub struct KeyInfoResp {
    pub key: Vec<u8>,
    pub version: String,
    pub algorithm: String,
}

impl KeyInfoResp {
    pub fn new(key: Vec<u8>, version: String, algorithm: String) -> Self {
        Self {
            key,
            version,
            algorithm,
        }
    }
}

#[derive(Debug)]
pub struct SignResponse {
    pub signature: Vec<u8>,
    pub key_version: String,
}

impl SignResponse {
    pub fn new(signature: Vec<u8>, key_version: String) -> Self {
        Self { signature, key_version }
    }
}
