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

use std::sync::Arc;
#[cfg(feature = "mysql_mode")]
use crate::services::mysql_mode;
#[cfg(feature = "redis_mode")]
use crate::services::redis_mode;
use crate::services::rv_trait::RefValueTrait;

pub struct RvFactory;

impl RvFactory {
    #[cfg(feature = "mysql_mode")]
    pub fn create_ref_value() -> Arc<impl RefValueTrait> {
        Arc::new(mysql_mode::rv_mysql_impl::RvMysqlImpl::new())
    }

    #[cfg(feature = "redis_mode")]
    pub fn create_ref_value() -> Arc<impl RefValueTrait> {
        Arc::new(redis_mode::rv_redis_impl::RvRedisImpl::new())
    }
}
