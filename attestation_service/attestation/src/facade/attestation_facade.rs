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

use actix_web::{web, HttpRequest};

use crate::entities::attest_request::AttestRequest;
use crate::strategy::attestation_strategy::AttestFuture;
use crate::{
    factory::attestation_factory::{AttestationFactory, AttestationType},
    strategy::attestation_strategy::AttestationStrategy,
};

pub struct AttestationFacade {
    strategy: Box<dyn AttestationStrategy>,
}

impl AttestationFacade {
    pub fn new(attestation_type: AttestationType) -> Self {
        Self { strategy: AttestationFactory::create_strategy(attestation_type) }
    }

    pub fn process_attestation<'a>(
        &'a self,
        request: &'a web::Json<AttestRequest>,
        http_req: &'a HttpRequest,
    ) -> AttestFuture<'a> {
        self.strategy.attest(request, http_req)
    }
}
