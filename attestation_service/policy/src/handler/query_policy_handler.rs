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

use std::vec::Vec;

use sea_orm::DatabaseConnection;
use key_management::api::{CryptoOperations, DefaultCryptoImpl};

use crate::entities::{policy::Policy, signature_policy::SignaturePolicy};
use crate::error::policy_error::PolicyError;
use crate::repositories::policy_repository::PolicyRepository;
use crate::constants::SIGNATURE_KEY_TYPE;
use config_manager::types::CONFIG;

pub struct QueryPolicyHandler;


impl QueryPolicyHandler {
    pub async fn get_policies_by_ids(
        db: &DatabaseConnection,
        policy_ids: Vec<String>,
    ) -> Result<Vec<Policy>, PolicyError> {
        let signature_policies = match PolicyRepository::get_correct_policies_by_ids(&db, policy_ids.clone()).await {
            Ok(policies) => policies,
            Err(e) => return Err(PolicyError::DatabaseOperationError(e.to_string())),
        };
    
        if signature_policies.len() != policy_ids.len() {
            let found_ids: std::collections::HashSet<_> = signature_policies.iter().map(|p| p.policy_id.clone()).collect();
            let missing_ids: Vec<_> = policy_ids.into_iter().filter(|id| !found_ids.contains(id)).collect();
            return Err(PolicyError::PolicyNotFoundError(format!("Policy not found for ids: {:?}", missing_ids)));
        }
    
        let verified_policies = Self::verify_signature_policies(signature_policies, &db).await?;
        Ok(verified_policies.into_iter().map(Policy::from).collect())
    }

    pub async fn get_default_policies_by_type(
        db: &DatabaseConnection,
        attester_type: String,
    ) -> Result<Vec<Policy>, PolicyError> {
        let signature_policies = match PolicyRepository::get_default_policies_by_type(db, attester_type).await {
            Ok(policies) => policies,
            Err(e) => return Err(PolicyError::DatabaseOperationError(e.to_string())),
        };

        if signature_policies.is_empty() {
            return Ok(Vec::new());
        }

        let verified_policies = Self::verify_signature_policies(signature_policies, &db).await?;
        Ok(verified_policies.into_iter().map(Policy::from).collect())
    }

    async fn verify_signature_policies(signature_policies: Vec<SignaturePolicy>, db: &DatabaseConnection) -> Result<Vec<SignaturePolicy>, PolicyError> {
        let config = CONFIG.get_instance().unwrap();
        let is_require_sign = config.attestation_service.key_management.is_require_sign;
        let mut correct_signature_policies = Vec::new();
        if is_require_sign {
            let crypto_ops = DefaultCryptoImpl;
            for policy in signature_policies.iter() {
                let data = policy.encode_to_bytes();
                match crypto_ops.verify(SIGNATURE_KEY_TYPE, Some(&policy.key_version), data, policy.signature.clone()).await {
                    Ok(true) => correct_signature_policies.push(policy.clone()),
                    Ok(false) => {
                        PolicyRepository::set_is_corrupted_use_connection(&db, policy.policy_id.clone()).await?;
                    },
                    Err(e) => {
                        return Err(PolicyError::PolicySignatureVerificationError(e.to_string()))
                    }
                }
            }
        } else {
            correct_signature_policies = signature_policies.clone();
        }

        Ok(correct_signature_policies)
    }
}