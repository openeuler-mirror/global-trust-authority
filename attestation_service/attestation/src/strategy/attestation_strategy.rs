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

use std::{future::Future, pin::Pin};

use actix_web::{web, HttpResponse, HttpRequest};

use crate::{entities::attest_request::AttestRequest, error::attestation_error::AttestationError};

type AttestResult = Result<HttpResponse, AttestationError>;
pub type AttestFuture<'a> = Pin<Box<dyn Future<Output = AttestResult> + Send + 'a>>;

pub trait AttestationStrategy {
    fn attest<'a>(
        &'a self,
        request: &'a web::Json<AttestRequest>,
        http_req: &'a HttpRequest
    ) -> AttestFuture<'a>;
}