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

use actix_web::{web, HttpResponse};
use serde_json::json;
use validator::Validate;
use common_log::{error, info};
use nonce::Nonce;
use plugin_manager::{PluginManager, PluginManagerInstance, ServicePlugin, ServiceHostFunctions};

use crate::{
    constants::SERVICE_VERSION,
    entities::challenge_request::ChallengeRequest,
    error::attestation_error::AttestationError,
};

/// Service struct for handling challenge-related operations
pub struct ChallengeService;

impl ChallengeService {
    /// Generates a new nonce for attestation challenge
    ///
    /// # Arguments
    /// * `challenge_request` - JSON payload containing agent version and attester types
    ///
    /// # Returns
    /// * `Result<HttpResponse, AttestationError>` - On success, returns HTTP response with service version and nonce
    ///                                            - On failure, returns appropriate error
    pub async fn generate_nonce(challenge_request: web::Json<ChallengeRequest>) -> Result<HttpResponse, AttestationError> {
        if let Err(err) = challenge_request.validate() {
            return Err(AttestationError::InvalidParameter(err.to_string()));
        }
        let challenge_request = challenge_request.into_inner();
        info!("Start checking plugins and generating nonce");

        if !Self::use_attester_types_get_plugins(&challenge_request) {
            error!("Required plugins not found");
            return Err(AttestationError::PluginNotFoundError("Required plugins not found".to_string()));
        }

        info!("Plugins verified, start generating nonce");
        let nonce = Nonce::generate().await;
        info!("Nonce generated successfully");
        Ok(HttpResponse::Ok().json(json!({
            "service_version": SERVICE_VERSION,
            "nonce": nonce
        })))
    }

    fn use_attester_types_get_plugins(challenge_request: &ChallengeRequest) -> bool {
        let manager = PluginManager::<dyn ServicePlugin, ServiceHostFunctions>::get_instance();
        for attester_type in &challenge_request.attester_type {
            let plugin_result = manager.get_plugin(attester_type);
            if plugin_result.is_none() {
                return false;
            }
        }
        true
    }
}
