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

use actix_web::web;
use ratelimit::Governor;

pub struct RemoteRouteConfigurator;

impl RemoteRouteConfigurator {
    pub fn new() -> Self {
        Self
    }
}

impl super::register::RouteConfigurator for RemoteRouteConfigurator {
    fn register_routes(&self, cfg: &mut web::ServiceConfig, management_governor: Governor) {
    }
}