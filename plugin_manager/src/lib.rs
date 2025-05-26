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

/// Plugin interface library for dynamic plugin loading

mod host_functions;
mod traits;
mod manager;

// Re-export all public items explicitly
// From interface
pub use traits::PluginBase;
pub use traits::ServicePlugin;
pub use traits::AgentPlugin;
pub use traits::PluginManagerInstance;
pub use traits::PluginError;

// From host_functions.rs
pub use host_functions::HostFunctions;
pub use host_functions::ServiceHostFunctions;
pub use host_functions::AgentHostFunctions;
pub use host_functions::ValidateCertChainFn;
pub use host_functions::GetUnmatchedMeasurementsFn;
pub use host_functions::QueryConfigurationFn;

// From manager.rs
pub use manager::PluginManager;
pub use manager::PluginEntry;
pub use manager::CreatePluginFn;

// Re-export serde_json only for tests and test plugins
#[cfg(any(test, feature = "test-plugins"))]
pub use serde_json;
