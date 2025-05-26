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

use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct NonceInfo {
    iat: i64,
    value: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NonceResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    service_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<NonceInfo>,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum CertType {
    RefValue,

    Policy,

    #[serde(rename = "tpm_boot")]
    #[clap(name = "tpm_boot")]
    TpmBoot,

    #[serde(rename = "tpm_ima")]
    #[clap(name = "tpm_ima")]
    TpmIma,

    Crl,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum UpdateCertType {
    RefValue,

    Policy,

    #[serde(rename = "tpm_boot")]
    #[clap(name = "tpm_boot")]
    TpmBoot,

    #[serde(rename = "tpm_ima")]
    #[clap(name = "tpm_ima")]
    TpmIma,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum DeleteType {
    Id,
    Type,
    All,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum PolicyDeleteType {
    Id,
    #[serde(rename = "attester_type")]
    #[clap(name = "attester_type")]
    AttesterType,
    All,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum ContentType {
    Jwt,
    Text,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum NonceType {
    Ignore,
    User,
    Default,
}

impl fmt::Display for NonceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NonceType::Ignore => write!(f, "ignore"),
            NonceType::User => write!(f, "user"),
            NonceType::Default => write!(f, "default"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub(crate) token: String,
}

