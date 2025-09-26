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

use base64::{engine::general_purpose, Engine as _};
use plugin_manager::PluginError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Cursor, Read};
use tpm_common_verifier::PcrValues;

use crate::evidence::Log;
use crate::verifier::AscendNpuPlugin;
use common_verifier::ImaLog;

/// IMA template entry structure for binary runtime measurements (ima-ng format only)
#[derive(Debug, Clone)]
pub struct ImaTemplateEntry {
    /// PCR index (4 bytes)
    pub pcr_index: u32,
    /// Template data hash (32 bytes for SHA256 in ima-ng format)
    pub template_data_hash: Vec<u8>,
    /// Template name length (4 bytes)
    pub template_name_len: u32,
    /// Template name (only "ima-ng" is supported)
    pub template_name: String,
    /// Template data length (4 bytes)
    pub template_data_len: u32,
    /// Template data (file hash + file path)
    pub template_data: Vec<u8>,
}


/// Log verification result
#[derive(Debug, Serialize, Deserialize)]
pub struct LogResult {
    pub log_status: String,
    pub ref_value_match_status: String,
    pub log_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_data: Option<Value>,
}

impl LogResult {
    /// Create successful log verification result
    pub fn success(log_type: String, log_status: String, ref_value_match_status: String) -> Self {
        Self {
            log_status,
            ref_value_match_status,
            log_type,
            log_data: None,
        }
    }

    /// Create failed log verification result
    pub fn failure(log_type: String, log_status: String, ref_value_match_status: String) -> Self {
        Self {
            log_status,
            ref_value_match_status,
            log_type,
            log_data: None,
        }
    }

    /// Convert to JSON value
    pub fn to_json_value(&self) -> Value {
        serde_json::json!({
            "log_status": self.log_status,
            "ref_value_match_status": self.ref_value_match_status,
            "log_type": self.log_type,
            "log_data": self.log_data
        })
    }
}

/// Parse IMA binary runtime measurement log (ima-ng format only)
/// Parse IMA binary log data into template entries
/// 
/// # Errors
/// 
/// This function will return an error if:
/// - The log data is malformed
/// - Template parsing fails
/// - UTF-8 conversion fails
pub fn parse_ima_binary_log(log_data: &[u8]) -> Result<Vec<ImaTemplateEntry>, PluginError> {
    let mut cursor = Cursor::new(log_data);
    let mut entries = Vec::new();
    
    
    while cursor.position() < log_data.len() as u64 {
        let entry = parse_ima_entry(&mut cursor)?;
        entries.push(entry);
    }
    
    Ok(entries)
}

/// Parse a single IMA template entry from binary cursor
fn parse_ima_entry(cursor: &mut Cursor<&[u8]>) -> Result<ImaTemplateEntry, PluginError> {
    // Read PCR index (4 bytes)
    let pcr_index = read_u32_le(cursor, "PCR index")?;
    
    // Read template data hash (32 bytes for SHA256 in ima-ng format)
    let template_data_hash = read_bytes(cursor, 32, "template data hash")?;
    
    // Read template name length (4 bytes)
    let template_name_len = read_u32_le(cursor, "template name length")?;
    
    // Read template name
    let template_name_bytes = read_bytes(cursor, template_name_len as usize, "template name")?;
    let template_name = String::from_utf8(template_name_bytes)
        .map_err(|e| PluginError::InputError(format!("Invalid template name UTF-8: {}", e)))?;
    
    // Read template data length (4 bytes)
    let template_data_len = read_u32_le(cursor, "template data length")?;
    
    // Read template data
    let template_data = read_bytes(cursor, template_data_len as usize, "template data")?;
    
    Ok(ImaTemplateEntry {
        pcr_index,
        template_data_hash,
        template_name_len,
        template_name,
        template_data_len,
        template_data,
    })
}

/// Read a 32-bit little-endian unsigned integer from binary cursor
fn read_u32_le(cursor: &mut Cursor<&[u8]>, field_name: &str) -> Result<u32, PluginError> {
    let mut bytes = [0u8; 4];
    cursor.read_exact(&mut bytes)
        .map_err(|e| PluginError::InputError(format!("Failed to read {}: {}", field_name, e)))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Read a specified number of bytes from binary cursor
fn read_bytes(cursor: &mut Cursor<&[u8]>, count: usize, field_name: &str) -> Result<Vec<u8>, PluginError> {
    let mut bytes = vec![0u8; count];
    cursor.read_exact(&mut bytes)
        .map_err(|e| PluginError::InputError(format!("Failed to read {}: {}", field_name, e)))?;
    Ok(bytes)
}


/// Parse IMA template data to extract file path and hash (ima-ng format only)
/// Parse IMA template data (ima-ng format only)
/// 
/// # Errors
/// 
/// This function will return an error if:
/// - Template data is malformed
/// - Unsupported template format
/// - UTF-8 conversion fails
pub fn parse_ima_template_data(template_data: &[u8], template_name: &str) -> Result<(Vec<u8>, String), PluginError> {
    match template_name {
        "ima-ng" => {
            // IMA-NG template: file_hash (32 bytes) + file_path (variable length)
            if template_data.len() < 32 {
                return Err(PluginError::InputError("IMA-NG template data too short".to_string()));
            }
            
            let file_hash = template_data[..32].to_vec();
            let file_path_bytes = &template_data[32..];
            
            // Find null terminator for file path
            let null_pos = file_path_bytes.iter().position(|&b| b == 0).unwrap_or(file_path_bytes.len());
            let file_path = String::from_utf8(file_path_bytes[..null_pos].to_vec())
                .map_err(|e| PluginError::InputError(format!("Invalid file path UTF-8: {}", e)))?;
            
            Ok((file_hash, file_path))
        },
        _ => {
            Err(PluginError::InputError(format!(
                "Unsupported IMA template: '{}'. Only 'ima-ng' format is supported",
                template_name
            )))
        }
    }
}

/// Verify single log
async fn verify_single_log(
    log: &Log,
    plugin: &AscendNpuPlugin,
    user_id: &str,
    node_id: Option<&str>,
    pcrs: &PcrValues,
) -> Result<LogResult, PluginError> {

    match log.log_type.as_str() {
        "boot_measurement" => verify_boot_measurement(log, plugin, user_id, node_id).await,
        "runtime_measurement" => verify_runtime_measurement(log, plugin, user_id, node_id, pcrs).await,
        _ => {
            let message = format!("Unsupported log type: {}", log.log_type);
            log::warn!("{}", message);
            Ok(LogResult::failure(log.log_type.clone(), "replay_failure".to_string(), "ignore".to_string()))
        }
    }
}

/// Verify boot measurement log
/// 
/// Note: Boot log format is currently undetermined, so this function
/// always returns verification failure until the format is defined.
async fn verify_boot_measurement(
    log: &Log,
    _plugin: &AscendNpuPlugin,
    _user_id: &str,
    _node_id: Option<&str>,
) -> Result<LogResult, PluginError> {
    // TODO: Implement boot measurement log verification
    // - Determine the correct boot log format for AscendNPU
    // - Parse boot log entries (kernel, initrd, bootloader, etc.)
    // - Verify boot log integrity and authenticity
    // - Implement PCR replay for boot measurements
    // - Add support for different boot log formats (UEFI, GRUB, etc.)
    log::warn!("Boot measurement log verification is not implemented - format is undetermined");
    
    // Decode base64 log data to validate format
    let _log_data = general_purpose::STANDARD.decode(&log.log_data)
        .map_err(|e| PluginError::InputError(format!("Failed to decode base64 boot measurement log: {}", e)))?;
    
    
    // Return failure since boot log format is undetermined
    Ok(LogResult::failure(
        log.log_type.clone(),
        "replay_failure".to_string(),
        "ignore".to_string()
    ))
}

/// Verify runtime measurement log using `ImaLog`'s verify function with proper PCR validation
async fn verify_runtime_measurement(
    log: &Log,
    plugin: &AscendNpuPlugin,
    user_id: &str,
    _node_id: Option<&str>,
    pcrs: &PcrValues,
) -> Result<LogResult, PluginError> {
    
    // Decode and validate log data
    let log_data = decode_log_data(log)?;
    
    // Use ImaLog to parse binary log data directly (since we have binary data)
    let mut ima_log = ImaLog::from_binary(&log_data, &pcrs.hash_alg)?;
    
    // Use ImaLog's verify function to perform actual verification
    let mut pcrs_clone = pcrs.clone();
    let (replay_result, ref_value_result) = match ima_log.verify(
        &mut pcrs_clone,
        plugin.get_host_functions(),
        user_id,
        plugin.get_plugin_type(),
    ).await {
        Ok(res) => res,
        Err(e) => {
            log::error!("IMA log verification failed: {}", e);
            (false, false)
        }
    };
    
    let ima_log_json = ima_log.to_json_value()?;
    
    let ref_value_match_result = if !replay_result {
        "ignore".to_string()
    } else if ref_value_result {
        "matched".to_string()
    } else {
        "unmatched".to_string()
    };

    let result = LogResult {
        log_status: if replay_result { "replay_success".to_string() } else { "replay_failure".to_string() },
        ref_value_match_status: ref_value_match_result,
        log_type: log.log_type.clone(),
        log_data: Some(ima_log_json),
    };
    
    Ok(result)
}

/// Decode base64 log data and validate it's not empty
fn decode_log_data(log: &Log) -> Result<Vec<u8>, PluginError> {
    // Decode base64 log data
    let log_data = general_purpose::STANDARD.decode(&log.log_data)
        .map_err(|e| PluginError::InputError(format!("Failed to decode base64 runtime measurement log: {}", e)))?;

    // Check if data is empty
    if log_data.is_empty() {
        return Err(PluginError::InputError("Runtime measurement log data is empty".to_string()));
    }

    Ok(log_data)
}


/// Verify all logs
/// 
/// Note: Logs are optional in `AscendNPU` evidence. If no logs are provided,
/// verification will still pass as long as other evidence components are valid.
/// Verify all logs in the evidence
/// 
/// # Errors
/// 
/// This function will return an error if:
/// - Log verification fails
/// - Log parsing fails
/// - PCR validation fails
pub async fn verify_all_logs(
    logs: &[Log],
    plugin: &AscendNpuPlugin,
    user_id: &str,
    node_id: Option<&str>,
    pcrs: &PcrValues,
) -> Result<Vec<LogResult>, PluginError> {
    let mut results = Vec::new();


    // Process each log individually
    for log in logs {
        match verify_single_log(log, plugin, user_id, node_id, pcrs).await {
            Ok(result) => results.push(result),
            Err(e) => {
                log::error!("Failed to verify log type {}: {}", log.log_type, e);
                results.push(LogResult::failure(
                    log.log_type.clone(),
                    "replay_failure".to_string(),
                    "ignore".to_string()
                ));
            }
        }
    }

    
    Ok(results)
}
