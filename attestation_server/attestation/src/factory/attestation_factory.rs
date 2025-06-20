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

use crate::strategy::attestation_strategy::AttestationStrategy;
use crate::strategy::strategy_impl::default::DefaultAttestationStrategy;

pub enum AttestationType {
    Default,
}

pub struct AttestationFactory;

impl AttestationFactory {
    pub fn create_strategy(attestation_type: AttestationType) -> Box<dyn AttestationStrategy> {
        match attestation_type {
            AttestationType::Default => Box::new(DefaultAttestationStrategy::new()),
        }
    }
}