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

use std::sync::RwLock;
use std::collections::HashMap;
use lazy_static::lazy_static;
use common_log::{error, info, warn};
use crate::handler::export_policy_handler::ExportPolicyHandler;
use crate::error::policy_error::PolicyError;

// Use lazy_static to create a global cache for storing export policy content of different attester_types
lazy_static! {
    static ref EXPORT_POLICY_CACHE: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());
}

/// Get the export policy for the specified attester_type
/// 
/// # Arguments
/// * `attester_type` - Challenge plugin type
/// 
/// # Returns
/// * `Result<String, PolicyError>` - Returns policy content string on success, error on failure
/// 
/// # Error
/// 
/// * `PolicyError::InternalError` - Failed to acquire read lock on export policy cache
pub fn get_export_policy(attester_type: &str) -> Result<String, PolicyError> {
    let cache_lock = &EXPORT_POLICY_CACHE;
    if let Some(content) = ExportPolicyHandler::get_policy_from_cache(attester_type, cache_lock)? {
        return Ok(content);
    }
    let policy_file_path = ExportPolicyHandler::get_policy_file_path(attester_type)?;
    let content = ExportPolicyHandler::read_policy_file(&policy_file_path)?;
    ExportPolicyHandler::cache_policy(attester_type, content.clone(), cache_lock)?;
    
    Ok(content)
}

/// Clear the cached policy in memory for the specified attester_type
/// 
/// # Arguments
/// * `attester_type` - Challenge plugin type
/// 
/// # Returns
/// * `Result<bool, PolicyError>` - Returns Ok(true/false) on success, error on failure
/// 
/// # Error
/// * `PolicyError::InternalError` - Failed to acquire write lock on export policy cache
/// * `PolicyError::NotFound` - No export policy found for the specified attester_type
pub fn unload_export_policy(attester_type: &str) -> Result<bool, PolicyError> {
    let cache_lock = &EXPORT_POLICY_CACHE;
    let mut cache = cache_lock.write().map_err(|e| {
        error!("Failed to acquire write lock on export policy cache: {}", e);
        PolicyError::InternalError(format!("Failed to acquire write lock: {}", e))
    })?;
    
    if cache.remove(attester_type).is_some() {
        info!("Unloaded export policy for attester_type: {}", attester_type);
        Ok(true)
    } else {
        warn!("No export policy found for attester_type: {}", attester_type);
        Ok(false)
    }
}