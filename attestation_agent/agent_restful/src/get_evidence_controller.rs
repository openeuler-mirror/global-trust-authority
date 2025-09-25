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

use crate::response_error::{create_error_response, create_challenge_error_response};
use actix_web::{http::StatusCode, HttpResponse};
use challenge::evidence::{EvidenceManager, GetEvidenceRequest};
use log::info;
use serde_json::Value;
use std::thread;

/// Main entry point for evidence collection requests
/// Processes the request and returns collected evidence
pub fn get_evidence(body: Option<Value>) -> HttpResponse {
    info!("Start collecting evidence");

    // Parse and sanitize the request body, or use default if none provided
    let evidence_request = match body {
        Some(value) => match serde_json::from_value::<GetEvidenceRequest>(value) {
            Ok(req) => {
                let sanitized = req.sanitize();
                if let Err(e) = sanitized.validate() {
                    return create_challenge_error_response(e);
                }
                sanitized
            },
            Err(e) => {
                return create_error_response(e, StatusCode::BAD_REQUEST);
            },
        },
        None => GetEvidenceRequest::default(),
    };

    let handle = thread::spawn(move || EvidenceManager::get_evidence(&evidence_request));

    match handle.join() {
        Ok(result) => match result {
            Ok(response) => HttpResponse::Ok().json(response),
            Err(error) => create_challenge_error_response(error),
        },
        Err(_) => create_error_response("Thread execution failed", StatusCode::INTERNAL_SERVER_ERROR),
    }
}
