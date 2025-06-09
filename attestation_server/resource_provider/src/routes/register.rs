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
#[cfg(feature = "co-deployment")]
use crate::routes::local::LocalRouteConfigurator;
#[cfg(feature = "independent-deployment")]
use crate::routes::remote::RemoteRouteConfigurator;

pub trait RouteConfigurator {
    fn register_routes(&self, cfg: &mut web::ServiceConfig, management_governor:Governor);
}

// Select implementation based on features
#[cfg(feature = "co-deployment")]
pub fn get_route_configurator() -> impl RouteConfigurator {
    LocalRouteConfigurator::new()
}

#[cfg(feature = "independent-deployment")]
pub fn get_route_configurator() -> impl RouteConfigurator {
    RemoteRouteConfigurator::new()  // empty implementation
}