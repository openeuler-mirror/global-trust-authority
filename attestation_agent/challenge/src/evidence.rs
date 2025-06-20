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

use serde::Deserialize;
use serde_json;
use crate::challenge_error::ChallengeError;
use crate::challenge::{
    collect_evidences_core, get_node_id, validate_nonce_fields, AttesterInfo, GetEvidenceResponse, Nonce,
};

/// Request structure for evidence collection, including nonce and attester info
#[derive(Debug, Deserialize, Default)]
pub struct GetEvidenceRequest {
    // Optional list of attester types to collect evidence from
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_types: Option<Vec<String>>,

    // Type of nonce to use (default or user-provided)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_type: Option<String>,

    // User-provided nonce value when nonce_type is "user"
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_nonce: Option<String>,

    // Server-generated nonce information
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,

    // Additional attestation data
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<serde_json::Value>,
}

impl GetEvidenceRequest {
    /// Sanitizes the request by converting empty values to None, for robust downstream logic
    /// Sanitizes the request by converting empty values to None:
    /// - Empty vectors become None
    /// - Empty or whitespace-only strings become None
    /// - Keeps nonce field as is (handled separately)
    pub fn sanitize(self) -> Self {
        GetEvidenceRequest {
            attester_types: self.attester_types.filter(|types| !types.is_empty()),
            nonce_type: self.nonce_type.filter(|t| !t.trim().is_empty()),
            user_nonce: self.user_nonce.filter(|n| !n.trim().is_empty()),
            nonce: self.nonce,
            attester_data: self.attester_data.filter(|d| !d.is_null()),
        }
    }
}

/// Manager for evidence collection logic
pub struct EvidenceManager;

impl EvidenceManager {
    /// Handles nonce type and value extraction based on request
    /// Validates and returns nonce type and value for evidence collection
    fn process_nonce(
        nonce_type: Option<&str>,
        user_nonce: Option<&String>,
        nonce: Option<&Nonce>,
    ) -> Result<(String, Option<String>), ChallengeError> {
        let nonce_type = nonce_type.map_or_else(|| "default".to_string(), |t| t.to_lowercase());

        let nonce_value = match nonce_type.as_str() {
            "ignore" => None,
            "user" => {
                let user_nonce_str = if let Some(n) = user_nonce {
                    n
                } else {
                    log::error!("User nonce not provided but nonce_type is 'user'");
                    return Err(ChallengeError::UserNonceNotProvided);
                };
                let user_nonce_len = user_nonce_str.len();
                if !(64..=1024).contains(&user_nonce_len) {
                    log::error!("user_nonce length invalid: {} bytes", user_nonce_len);
                    return Err(ChallengeError::NonceInvalid(format!(
                        "user_nonce length must be between 64 and 1024 bytes, got {} bytes",
                        user_nonce_len
                    )));
                }
                user_nonce_str.clone().into()
            },
            "default" => {
                let nonce = if let Some(n) = nonce {
                    n
                } else {
                    log::error!("Nonce not provided but nonce_type is 'default'");
                    return Err(ChallengeError::NonceNotProvided);
                };
                if let Err(e) = validate_nonce_fields(nonce) {
                    log::error!("Nonce validation failed: {}", e);
                    return Err(e);
                }
                Some(nonce.value.clone())
            },
            _ => {
                log::error!("Invalid nonce_type: '{}'", nonce_type);
                return Err(ChallengeError::NonceTypeError(format!(
                    "Invalid nonce_type: '{}'. Must be one of: ignore, user, default",
                    nonce_type
                )));
            },
        };

        Ok((nonce_type, nonce_value))
    }

    /// Main function to collect evidence based on the request
    ///
    /// # Errors
    ///
    /// Returns an error if the evidence cannot be retrieved.
    pub fn get_evidence(request: &GetEvidenceRequest) -> Result<GetEvidenceResponse, ChallengeError> {
        log::info!("Starting evidence collection");

        let (nonce_type, nonce_value) =
            Self::process_nonce(request.nonce_type.as_deref(), request.user_nonce.as_ref(), request.nonce.as_ref())?;

        let attester_info = request.attester_types.as_ref().map(|types| {
            types.iter().map(|t| AttesterInfo { attester_type: Some(t.clone()), policy_ids: None }).collect::<Vec<_>>()
        });

        let evidences = collect_evidences_core(&attester_info, &nonce_value)?;

        let node_id = get_node_id()?;

        Ok(GetEvidenceResponse::new(
            env!("CARGO_PKG_VERSION"),
            &nonce_type,
            request.user_nonce.as_ref(),
            request.nonce.as_ref(),
            request.attester_data.as_ref(),
            &node_id,
            evidences,
        ))
    }
}
