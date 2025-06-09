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

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;
use std::{cmp::Ordering, ops::Deref};

/**
 * Signing Key Input Parameters
 */
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub version: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/**
 * Verify and Update Signature Input Parameters
 */
#[derive(Debug)]
pub struct VerifyAndUpdateParam {
    pub key_type: String,
    pub key_version: String,

    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Version(String);

impl Version {
    pub fn new(version: &str) -> Self {
        Self(version.to_string())
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn parse_version_number(version: &Version) -> Result<u32, String> {
    version
        .0
        .trim_start_matches('v')
        .parse()
        .map_err(|e| format!("Invalid version format: {}", e))
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(parse_version_number(self).cmp(&parse_version_number(other)))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        parse_version_number(self).cmp(&parse_version_number(other))
    }
}

impl Deref for Version {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrivateKey(pub String);

impl Deref for PrivateKey {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Algorithm(pub String);

impl Deref for Algorithm {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Encoding(pub String);

impl Deref for Encoding {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct KeyVersionModel {
    #[serde(rename = "version")]
    pub version: Version,
    #[serde(rename = "private_key")]
    pub private_key: PrivateKey,
    #[serde(rename = "algorithm")]
    pub algorithm: Algorithm,
    #[serde(rename = "encoding")]
    pub encoding: Encoding,
}

/**
 * Vault API Response
 */
#[derive(Debug, Deserialize, Clone)]
pub struct VaultResponse {
    #[serde(rename = "FSK")]
    pub fsk: Vec<KeyVersionModel>, // file signature key
    #[serde(rename = "NSK")]
    pub nsk: Vec<KeyVersionModel>, // nonce signature key
    #[serde(rename = "TSK")]
    pub tsk: Vec<KeyVersionModel>, // Token signature key
}

impl VaultResponse {
    // Find the largest version
    pub fn find_max_version(&self) -> Option<Version> {
        // Using Iterator: :chain merges three Vec into one iterator
        self.fsk
            .iter()
            .chain(self.nsk.iter())
            .chain(self.tsk.iter())
            .map(|key| key.version.clone())
            // Use the Ord trait implemented by Version for comparison
            .max()
    }
}

impl std::fmt::Display for VaultResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VaultResponse {{ fsk: {:?}, nsk: {:?}, ask: {:?} }}",
            self.fsk, self.nsk, self.tsk
        )
    }
}