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

use actix_web::{web, HttpRequest, HttpResponse};
use attestation::facade::attestation_facade::AttestationFacade;
use attestation::factory::attestation_factory::AttestationType;
use attestation::service::challenge_service::ChallengeService;
use attestation::constants::SERVICE_VERSION;
use attestation::entities::attest_request::AttestRequest;
use attestation::entities::challenge_request::ChallengeRequest;
use log::{error, info};
use serde_json::json;

/// Handles the nonce generation request
///
/// # Arguments
/// * `challenge_req` - JSON payload containing the challenge request details
/// * `req` - HTTP request containing required headers like User-Id
///
/// # Returns
/// * `HttpResponse` - On success, returns HTTP response with nonce and service version
///                  On failure, returns error response with appropriate message
pub async fn get_nonce(challenge_req: web::Json<ChallengeRequest>, req: HttpRequest) -> HttpResponse {
    info!("receive challenge request!");

    let user_id = req.headers().get("User-Id");
    if user_id.is_none() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Missing or Invalid User-Id header",
            "service_version": SERVICE_VERSION
        }));
    }

    ChallengeService::generate_nonce(challenge_req).await.unwrap_or_else(|err| {
        error!("Failed to generate nonce: {}", err);
        HttpResponse::build(err.status_code()).json(json!({
            "message": err.message(),
            "service_version": SERVICE_VERSION
        }))
    })
}

/// Handles the attestation request
///
/// # Arguments
/// * `request` - JSON payload containing the attestation request details
/// * `req` - HTTP request containing required headers
///
/// # Returns
/// * `HttpResponse` - On success, returns HTTP response with attestation result
///                  On failure, returns error response with appropriate message
pub async fn attest(request: web::Json<AttestRequest>, req: HttpRequest) -> HttpResponse {
    info!("receive attestation request!");

    let user_id = req.headers().get("User-Id");
    if user_id.is_none() {
        return HttpResponse::BadRequest().json(json!({
            "service_version": SERVICE_VERSION,
            "message": "Missing or Invalid User-Id header"
        }));
    }
    // if you need to support multiple types of attestation, you will need to create different facades based on the different types.
    let facade = AttestationFacade::new(AttestationType::Standard);

    facade.process_attestation(&request, &req).await.unwrap_or_else(|err| {
        error!("Failed to attest evidence: {}", err);
        HttpResponse::build(err.status_code()).json(json!({
            "service_version": SERVICE_VERSION,
            "message": err.message()
        }))
    })
}