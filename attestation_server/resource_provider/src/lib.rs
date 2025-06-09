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

#[cfg(feature = "co-deployment")]
mod local;

#[cfg(feature = "independent-deployment")]
mod restful;

pub mod factory;
pub mod error;

pub mod resource_facade;
pub mod routes;

// Ensure feature mutual exclusivity at compile time
#[cfg(all(
    feature = "co-deployment",
    feature = "independent-deployment"
))]
compile_error!(
    "`co-deployment` and `independent-deployment` cannot be enabled together. \
    Hint: When using `independent-deployment`, add `default-features = false`"
);