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

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use common_verifier::ImaLog;
use eventlog_rs::Eventlog;
use hex;
use openssl::sha::Sha256;
use plugin_manager::PluginError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryFrom;

use crate::{
    constants::{CVM_REM_ARR_SIZE, TEMPLATE_HASH_ALG},
    evidence::Log,
    verifier::VirtCCAPlugin,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SerializableDigest {
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SerializableEventEntry {
    pub target_measurement_registry: u32,
    pub event_type_id: u32,
    pub event_type: String,
    pub digests: Vec<SerializableDigest>,
    pub event_desc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SerializableEventlog {
    pub logs: Vec<SerializableEventEntry>,
}

impl From<&Eventlog> for SerializableEventlog {
    fn from(eventlog: &Eventlog) -> Self {
        let serializable_log = eventlog
            .log
            .iter()
            .map(|entry| SerializableEventEntry {
                target_measurement_registry: entry.target_measurement_registry,
                event_type_id: entry.event_type_id,
                event_type: entry.event_type.clone(),
                digests: entry
                    .digests
                    .iter()
                    .map(|digest| {
                        let mut hasher = Sha256::new();
                        hasher.update(&digest.digest);
                        let hashed_digest = hasher.finish();
                        SerializableDigest { algorithm: digest.algorithm.clone(), digest: hex::encode(hashed_digest) }
                    })
                    .collect(),
                event_desc: String::from_utf8_lossy(&entry.event_desc).into_owned(),
            })
            .collect();
        SerializableEventlog { logs: serializable_log }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirmwareState {
    pub grub_image_count: u8,
    pub grub_image_list: Vec<String>,
    pub state_hash: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogResult {
    pub log_status: String,
    pub ref_value_match_status: String,
    pub log_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_data: Option<Value>,
}

impl LogResult {
    pub fn to_json_value(&self) -> Value {
        let mut map = serde_json::Map::new();
        let prefix = match self.log_type.as_str() {
            "ImaLog" => "vcca_ima_",
            "CCEL" => "vcca_ccel_",
            _ => "",
        };
        map.insert(format!("{}log_status", prefix), Value::String(self.log_status.clone()));
        map.insert(format!("{}ref_value_match_status", prefix), Value::String(self.ref_value_match_status.clone()));
        if let Some(data) = &self.log_data {
            map.insert(format!("{}log_data", prefix), data.clone());
        }
        Value::Object(map)
    }
}

impl LogResult {
    pub fn new(log_type: String) -> Self {
        Self {
            log_status: "no_log".to_string(),
            ref_value_match_status: "ignore".to_string(),
            log_type,
            log_data: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct UefiVerify {}

impl UefiVerify {
    pub fn compare_rtmr_with_uefi_log(
        replayed_rtmr: &HashMap<u32, Vec<u8>>,
        uefi_log_hash: &[Vec<u8>; CVM_REM_ARR_SIZE],
    ) -> bool {
        // UEFI only uses rem with index 0, 1, and 2.
        (1..CVM_REM_ARR_SIZE as u32).all(|i| {
            let index = i as usize - 1;
            replayed_rtmr
                .get(&i)
                .map(|rtmr_value| {
                    rtmr_value.len() == 32 && uefi_log_hash[index].len() == 32 && rtmr_value == &uefi_log_hash[index]
                })
                .unwrap_or(false)
        })
    }

    pub fn firmware_log_state(event_log: &Eventlog) -> Value {
        let grub_event_type: &str = "EV_EFI_BOOT_SERVICES_APPLICATION";
        let exclude_event_descs: &[&str] = &["grub_cmd:"];
        let event_descs: HashMap<_, _> =
            HashMap::from([("grub_cfg", "grub.cfg"), ("kernel", "/vmlinuz-"), ("initramfs", "/initramfs-")]);

        let mut state_data = serde_json::Map::new();
        let mut grub_image_list: Vec<Value> = Vec::new();

        //based event_type get grub image info
        for event_entry in event_log.log.iter() {
            if event_entry.event_type == grub_event_type {
                grub_image_list.push(Value::String(hex::encode(&event_entry.digests[0].digest)));
            } else {
                let event_desc = match std::str::from_utf8(&event_entry.event_desc) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if exclude_event_descs.iter().any(|&s| event_desc.contains(s)) {
                    continue;
                }
                for (&key, &pattern) in event_descs.iter() {
                    if !state_data.contains_key(key) && event_desc.contains(pattern) {
                        state_data.insert(
                            key.to_string(),
                            Value::String(hex::encode(&event_entry.digests[0].digest)),
                        );
                    }
                }
                if state_data.len() == event_descs.len() {
                    state_data.insert("grub_image_list".to_string(), Value::Array(grub_image_list));
                    return Value::Object(state_data);
                }
            }
        }

        state_data.insert("grub_image_list".to_string(), Value::Array(grub_image_list));
        Value::Object(state_data)
    }

    pub fn uefi_log_verify(
        uefi_log: &str,
        cvm_token_rem: [Vec<u8>; CVM_REM_ARR_SIZE],
        mut log_result: LogResult,
    ) -> Result<LogResult, PluginError> {
        if uefi_log.as_bytes().len() > 5 * 1024 * 1024 {
            return Err(PluginError::InputError("UEFI log size exceeds 5MB limit".to_string()));
        }

        let decode_uefi_log = general_purpose::STANDARD
            .decode(uefi_log)
            .map_err(|e| PluginError::InputError(format!("Failed to decode base64 log: {}", e)))?;
        let event_log = Eventlog::try_from(decode_uefi_log)
            .map_err(|e| PluginError::InputError(format!("Failed to parse UEFI event log: {}", e)))?;
        let replayed_rtmr = event_log.replay_measurement_registry();
        let serializable_event_log = SerializableEventlog::from(&event_log);
        let firmware_state = Self::firmware_log_state(&event_log);

        if UefiVerify::compare_rtmr_with_uefi_log(&replayed_rtmr, &cvm_token_rem) {
            log_result.log_status = "replay_success".to_string();
        } else {
            log_result.log_status = "replay_failure".to_string();
        }

        let mut log_data = serde_json::to_value(serializable_event_log).ok();
        if let Some(ref mut data) = log_data {
            data["firmware_state"] = firmware_state;
        }
        log_result.log_data = log_data;

        Ok(log_result)
    }
}

#[derive(Debug, Default)]
pub struct ImaVerify {}

impl ImaVerify {
    pub async fn ima_log_verify(
        ima_log: &str,
        cvm_token_rem: [Vec<u8>; CVM_REM_ARR_SIZE],
        mut log_result: LogResult,
        plugin: &VirtCCAPlugin,
        user_id: &str,
    ) -> Result<LogResult, PluginError> {
        let cvm_token_rem_hex: Vec<String> = cvm_token_rem.iter().map(|v| hex::encode(v)).collect();
        let mut parsed_ima_log = ImaLog::new(ima_log, TEMPLATE_HASH_ALG)
            .map_err(|e| PluginError::InputError(format!("Failed to parse IMA log: {}", e)))?;
        let replay_pcr_values = &parsed_ima_log.get_replay_pcr_values(cvm_token_rem_hex.clone(), TEMPLATE_HASH_ALG)?;
        log_result.log_status =
            if ImaVerify::check_replay_value_is_matched(replay_pcr_values.clone(), cvm_token_rem_hex.clone(), parsed_ima_log.clone()) {
                "replay_success".to_string()
            } else {
                "replay_failure".to_string()
            };
        let is_ref_value_match = &parsed_ima_log
            .check_reference_values(plugin.get_host_functions(), user_id, plugin.get_plugin_type())
            .await?;
        log_result.ref_value_match_status =
            if *is_ref_value_match { "matched".to_string() } else { "unmatched".to_string() };
        log_result.log_data = parsed_ima_log.to_json_value().ok();

        Ok(log_result)
    }

    fn check_replay_value_is_matched(replay_pcr_values: HashMap<u32, String>, cvm_token_rem: Vec<String>, ima_log: ImaLog) -> bool {
        // If there is no match between pcr and rem, return false.
        if ima_log.logs.len() - 1 != replay_pcr_values.len() {
            return false;
        }

        let mut all_matched = true;
        for (pcr_index, pcr_value) in replay_pcr_values {
            let cvm_token_rem_value = cvm_token_rem.get(pcr_index as usize - 1);
            if let Some(cvm_token_rem_value) = cvm_token_rem_value {
                if pcr_value != *cvm_token_rem_value {
                    all_matched = false;
                }
            }
        }
        all_matched
    }
}

#[async_trait]
pub trait LogVerification {
    async fn verify_log(
        &self,
        log_data: &str,
        cvm_token_rem: [Vec<u8>; CVM_REM_ARR_SIZE],
        log_result: LogResult,
        plugin: Option<&VirtCCAPlugin>,
        user_id: Option<&str>,
    ) -> Result<LogResult, PluginError>;
}

#[async_trait]
impl LogVerification for UefiVerify {
    async fn verify_log(
        &self,
        log_data: &str,
        cvm_token_rem: [Vec<u8>; CVM_REM_ARR_SIZE],
        log_result: LogResult,
        _plugin: Option<&VirtCCAPlugin>,
        _user_id: Option<&str>,
    ) -> Result<LogResult, PluginError> {
        UefiVerify::uefi_log_verify(log_data, cvm_token_rem, log_result)
    }
}

#[async_trait]
impl LogVerification for ImaVerify {
    async fn verify_log(
        &self,
        log_data: &str,
        cvm_token_rem: [Vec<u8>; CVM_REM_ARR_SIZE],
        log_result: LogResult,
        plugin: Option<&VirtCCAPlugin>,
        user_id: Option<&str>,
    ) -> Result<LogResult, PluginError> {
        let plugin = match plugin {
            Some(plugin) => plugin,
            _ => return Err(PluginError::InputError("plugin required for IMA log".to_string())),
        };
        let user_id = match user_id {
            Some(user_id) => user_id,
            None => return Err(PluginError::InputError("user_id required for IMA log".to_string())),
        };
        ImaVerify::ima_log_verify(log_data, cvm_token_rem, log_result, plugin, user_id).await
    }
}

pub async fn verify_all_logs(
    logs: Option<&Vec<Log>>,
    cvm_token_rem: [Vec<u8>; CVM_REM_ARR_SIZE],
    plugin: &VirtCCAPlugin,
    user_id: &str,
) -> Result<Vec<LogResult>, PluginError> {
    let mut log_results = Vec::new();
    let mut has_tcg_event_log = false;
    let mut has_ima_log = false;
    let uefi_verifier = UefiVerify::default();
    let ima_verifier = ImaVerify::default();
    if let Some(logs) = logs {
        if logs.len() > 2 {
            return Err(PluginError::InternalError("logs length should not exceed 2".to_string()));
        }
        for log in logs {
            match log.log_type.as_str() {
                "CCEL" => {
                    let result = uefi_verifier
                        .verify_log(
                            &log.log_data,
                            cvm_token_rem.clone(),
                            LogResult::new(log.log_type.clone()),
                            None,
                            None,
                        )
                        .await?;
                    log_results.push(result);
                    has_tcg_event_log = true;
                },
                "ImaLog" => {
                    let result = ima_verifier
                        .verify_log(
                            &log.log_data,
                            cvm_token_rem.clone(),
                            LogResult::new(log.log_type.clone()),
                            Some(plugin),
                            Some(user_id),
                        )
                        .await?;
                    log_results.push(result);
                    has_ima_log = true;
                },
                _ => return Err(PluginError::InputError("Invalid log type".to_string())),
            }
        }
    }
    if !has_tcg_event_log {
        log_results.push(LogResult::new("CCEL".to_string()));
    }
    if !has_ima_log {
        log_results.push(LogResult::new("ImaLog".to_string()));
    }
    Ok(log_results)
}
