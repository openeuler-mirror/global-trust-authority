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

#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use crate::resource_facade::{Endorsement, Policy, Rv};
#[cfg(feature = "co-deployment")]
use crate::local;
#[cfg(feature = "independent-deployment")]
use crate::restful;

#[cfg(feature = "independent-deployment")]
pub fn create_endorsement() -> Arc<impl Endorsement> {
    Arc::new(restful::impls::endorsement_impl::EndorsementImpl::new())
}

#[cfg(feature = "co-deployment")]
pub fn create_endorsement() -> Arc<impl Endorsement> {
    local::proxy::EndorsementProxy::instance().clone()
}

#[cfg(feature = "independent-deployment")]
pub fn create_policy() -> Arc<impl Policy> {
    Arc::new(restful::impls::policy_impl::PolicyImpl::new())
}

#[cfg(feature = "co-deployment")]
pub fn create_policy() -> Arc<impl Policy> {
    local::proxy::PolicyProxy::instance().clone()
}

#[cfg(feature = "independent-deployment")]
pub fn create_rv() -> Arc<impl Rv> {
    Arc::new(restful::impls::rv_impl::RvImpl::new())
}

#[cfg(feature = "co-deployment")]
pub fn create_rv() -> Arc<impl Rv> {
    local::proxy::RvProxy::instance().clone()
}
