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

// Common configuration for TPM plugins
use plugin_manager::PluginError;
use tss_esapi::tcti_ldr::TctiNameConf;
use std::str::FromStr;

#[derive(Debug)]
pub struct PcrSelection {
    pub banks: Vec<i32>,
    pub hash_alg: String,
}

#[derive(Debug)]
pub struct QuoteSignatureScheme {
    pub signature_alg: String,
    pub hash_alg: String,
}

#[derive(Debug)]
pub struct TpmPluginConfig {
    pub plugin_type: String,
    pub log_file_path: String,
    pub tcti_config: TctiNameConf,
    pub ak_handle: i64,
    pub ak_nv_index: i64,
    pub pcr_selection: PcrSelection,
    pub raw_config: serde_json::Value,
    pub quote_signature_scheme: Option<QuoteSignatureScheme>,
}

impl TpmPluginConfig {
    pub fn from_json(plugin_type: String, config_json: &str) -> Result<Self, PluginError> {
        // Parse plugin config
        let config: serde_json::Value = serde_json::from_str(config_json)
            .map_err(|e| PluginError::InternalError(format!("Failed to parse plugin configuration as JSON: {}", e)))?;
        
        let ak_handle: i64 = config
            .get("ak_handle")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| PluginError::InternalError("AK handle not found or invalid".to_string()))?;
        
        let ak_nv_index: i64 = config
            .get("ak_nv_index")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| PluginError::InternalError("AK NV index not found or invalid".to_string()))?;
        
        // Parse the new PCR selection structure
        let pcr_selection_obj = config
            .get("pcr_selections")
            .ok_or_else(|| PluginError::InternalError("PCR selections not found".to_string()))?;
        
        // Extract banks array
        let pcr_banks: Vec<i32> = pcr_selection_obj
            .get("banks")
            .and_then(|v| v.as_array())
            .map(|v| v.iter().filter_map(|x| x.as_i64().map(|x| x as i32)).collect())
            .ok_or_else(|| PluginError::InternalError("PCR banks not found or invalid".to_string()))?;
        
        // Extract hash algorithm
        let pcr_hash_alg: String = pcr_selection_obj
            .get("hash_alg")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| PluginError::InternalError("PCR hash algorithm not found".to_string()))?;
        
        let quote_signature_scheme = match config.get("quote_signature_scheme") {
            Some(scheme_value) => {
                match scheme_value.as_object() {
                    Some(scheme_obj) => {
                        let signature_alg = scheme_obj.get("signature_alg")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .ok_or_else(|| PluginError::InternalError("Quote signature algorithm not found".to_string()))?;
                        
                        let hash_alg = scheme_obj.get("hash_alg")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .ok_or_else(|| PluginError::InternalError("Quote hash algorithm not found".to_string()))?;
                        
                        Some(QuoteSignatureScheme { signature_alg, hash_alg })
                    },
                    None => return Err(PluginError::InternalError("Quote signature scheme is not an object".to_string()))
                }
            },
            None => None
        };

        let pcr_selection = PcrSelection {
            banks: pcr_banks,
            hash_alg: pcr_hash_alg,
        };
        
        // Get log file path
        let log_file_path = config
            .get("log_file_path")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| PluginError::InternalError("Log file path not found".to_string()))?;
        
        let tcti_config_name: String = config
            .get("tcti_config")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| PluginError::InternalError("TCTI configuration not found".to_string()))?;
        
        let tcti_config = TctiNameConf::from_str(&tcti_config_name)
            .map_err(|e| PluginError::InternalError(format!("Failed to create TCTI: {}", e)))?;
        
        Ok(Self {
            plugin_type,
            log_file_path,
            tcti_config,
            ak_handle,
            ak_nv_index,
            pcr_selection,
            raw_config: config,
            quote_signature_scheme,
        })
    }
}