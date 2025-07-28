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

// Plugin trait definitions

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use std::result::Result;

/// Management trait - shared by all plugins
#[async_trait]
pub trait PluginBase: Send + Sync {
    fn plugin_type(&self) -> &str;
}

#[async_trait]
pub trait ServicePlugin: PluginBase {
    fn get_sample_output(&self) -> Value;
    async fn verify_evidence(&self, user_id: &str, node_id: Option<&str>, evidence: &Value, nonce: Option<&[u8]>) -> Result<Value, PluginError>;
}

pub trait AgentPlugin: PluginBase {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>, log_types: Option<Vec<String>>) -> Result<Value, PluginError>;
}

/// Trait for getting singleton instances of plugin managers
pub trait PluginManagerInstance {
    fn get_instance() -> &'static Self;
}

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Input error: {0}")]
    InputError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}
