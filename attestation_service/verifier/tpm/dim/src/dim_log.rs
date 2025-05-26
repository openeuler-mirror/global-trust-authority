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

use serde_json::Value;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tpm_common_verifier::PcrValues;
use plugin_manager::{PluginError, ServiceHostFunctions};
use std::str::{self, FromStr};
use openssl::hash::{Hasher, MessageDigest};
use hex;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use std::fmt;

/// Supported hash algorithms for DIM logs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha1 => write!(f, "sha1"),
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha384 => write!(f, "sha384"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
            HashAlgorithm::Sm3 => write!(f, "sm3"),
        }
    }
}

impl HashAlgorithm {
    /// Get the expected length of the hash in hexadecimal characters
    pub const fn hex_length(&self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha384 => 96,
            Self::Sha512 => 128,
            Self::Sm3 => 64,
        }
    }

    /// Get the OpenSSL MessageDigest for this algorithm
    pub fn to_message_digest(&self) -> MessageDigest {
        match self {
            Self::Sha1 => MessageDigest::sha1(),
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
            Self::Sm3 => MessageDigest::sm3(),
        }
    }

    /// Validate if a string is a valid hex hash for this algorithm
    pub fn validate_hex_hash(&self, hash: &str) -> bool {
        hash.len() == self.hex_length() && hash.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl FromStr for HashAlgorithm {
    type Err = DimLogError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            "sm3" => Ok(Self::Sm3),
            _ => Err(DimLogError::ValidationError(format!("Unsupported hash algorithm: {}", s))),
        }
    }
}

/// Represents a single entry in the DIM log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimLogEntry {
    /// PCR register number
    pub pcr_index: u32,
    /// Hash of the template
    pub template_hash: String,
    /// Hash algorithm used for file hashing
    pub file_hash_alg: HashAlgorithm,
    /// Hash of the file
    pub file_hash: String,
    /// Path to the file
    pub file_path: String,
    /// Type of the log entry
    pub log_type: String,
    /// Whether the reference value matched
    pub ref_value_matched: Option<bool>,
}

/// Represents a complete DIM log with entries organized by PCR index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimLog {
    /// Map of PCR indices to their corresponding log entries
    pub logs: HashMap<u32, Vec<DimLogEntry>>,
}

/// Custom error type for DIM log operations
#[derive(Debug, Error)]
pub enum DimLogError {
    #[error("Input error: {0}")]
    InputError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl From<DimLogError> for PluginError {
    fn from(err: DimLogError) -> Self {
        match err {
            DimLogError::InputError(msg) => PluginError::InputError(msg),
            DimLogError::InternalError(msg) => PluginError::InternalError(msg),
            DimLogError::ValidationError(msg) => PluginError::InputError(msg),
        }
    }
}

/// Internal structure for parsed log entries
#[derive(Debug)]
pub struct ParsedLogEntry {
    pub pcr_index: u32,
    pub log_entry: DimLogEntry,
}

impl DimLog {
    /// Create a new DimLog from base64 encoded log data
    pub fn new(log_data: &str) -> Result<Self, DimLogError> {
        if log_data.is_empty() {
            return Err(DimLogError::InputError("Log data cannot be empty".to_string()));
        }

        let log_str = Self::decode_log_data(log_data)?;
        let mut logs = HashMap::new();

        for line in log_str.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            let entry = Self::parse_log_line(line)?;
            logs.entry(entry.pcr_index)
                .or_insert_with(Vec::new)
                .push(entry.log_entry);
        }

        Ok(Self { logs })
    }

    /// Verify the DIM log against PCR values and reference measurements
    pub async fn verify(
        &mut self,
        pcr_values: &mut PcrValues,
        service_host_functions: &ServiceHostFunctions,
        user_id: &str
    ) -> Result<bool, DimLogError> {
        // First verify PCR values to ensure log integrity
        self.replay_pcr_values(pcr_values)?;
        let pcr_match_result = pcr_values.check_is_matched().map_err(|e| DimLogError::InternalError(e.to_string()))?;

        // Only verify file hashes if PCR values match
        if pcr_match_result {
            let file_hashes = self.collect_file_hashes()?;
            let unmatched_hashes = self.get_unmatched_hashes(&file_hashes, service_host_functions, user_id).await?;
            self.update_ref_value_matches(&unmatched_hashes);
        }
        
        Ok(pcr_match_result)
    }

    /// Convert the DIM log to a JSON value
    pub fn to_json_value(&self) -> Result<Value, DimLogError> {
        serde_json::to_value(self)
            .map_err(|e| DimLogError::InternalError(e.to_string()))
    }

    /// Replay PCR values using the log entries
    pub fn replay_pcr_values(&self, pcr_values: &mut PcrValues) -> Result<(), DimLogError> {
        if self.logs.is_empty() {
            return Self::verify_empty_log_pcrs(pcr_values);
        }

        // 验证日志中的 PCR 索引
        for (&pcr_index, _) in &self.logs {
            if pcr_index > 23 {
                return Err(DimLogError::ValidationError(
                    format!("PCR index {} in log is out of valid range (0-23)", pcr_index)
                ));
            }
        }

        // 验证 PCR 索引
        let indices = pcr_values.get_pcr_indices();
        for pcr_index in indices {
            if pcr_index > 23 {
                return Err(DimLogError::ValidationError(
                    format!("PCR index {} is out of valid range (0-23)", pcr_index)
                ));
            }

            // Get current PCR value
            let pcr_value = match pcr_values.get_pcr_value(pcr_index) {
                Some(value) => value,
                None => continue,
            };

            // Check if we have logs for this PCR
            match self.logs.get(&pcr_index) {
                Some(logs) if !logs.is_empty() => {
                    // 克隆 logs，避免可变借用冲突
                    let logs_cloned = logs.clone();
                    let hash_alg_str = pcr_values.hash_alg.clone();
                    self.process_pcr_logs(pcr_index, &logs_cloned, &hash_alg_str, pcr_values)?;
                }
                _ => {
                    // No logs found, verify PCR value is initial
                    let initial_value = PcrValues::create_initial_pcr_value(&pcr_values.hash_alg, pcr_index, None)
                        .map_err(|e| DimLogError::InternalError(e.to_string()))?;

                    if pcr_value != initial_value {
                        return Err(DimLogError::ValidationError(
                            format!("PCR {} has been extended but no log entries found", pcr_index)
                        ));
                    }
                }
            }
        }
        
        Ok(())
    }

    /// 验证空日志时的 PCR 值
    fn verify_empty_log_pcrs(pcr_values: &PcrValues) -> Result<(), DimLogError> {
        // 验证哈希算法
        if pcr_values.hash_alg.is_empty() {
            return Err(DimLogError::ValidationError(
                "Hash algorithm cannot be empty".to_string()
            ));
        }

        let hash_alg = &pcr_values.hash_alg;
        let mut non_initial_pcrs = Vec::new();

        // 检查所有 PCR 值
        for &pcr_index in &pcr_values.get_pcr_indices() {
            // 验证 PCR 索引范围
            if pcr_index > 23 {
                return Err(DimLogError::ValidationError(
                    format!("PCR index {} is out of valid range (0-23)", pcr_index)
                ));
            }

            // 获取当前 PCR 值
            let pcr_value = match pcr_values.get_pcr_value(pcr_index) {
                Some(v) => v,
                None => continue,
            };

            // 获取初始值
            let initial_value = PcrValues::create_initial_pcr_value(hash_alg, pcr_index, None)
                .map_err(|e| DimLogError::InternalError(format!(
                    "Failed to create initial value for PCR {}: {}", pcr_index, e
                )))?;

            // 检查是否匹配初始值
            if pcr_value != initial_value {
                non_initial_pcrs.push(pcr_index);
            }
        }

        // 如果有非初始值的 PCR，返回错误
        if !non_initial_pcrs.is_empty() {
            return Err(DimLogError::ValidationError(format!(
                "PCRs {:?} are not initial values but log is empty",
                non_initial_pcrs
            )));
        }

        Ok(())
    }

    fn decode_log_data(log_data: &str) -> Result<String, DimLogError> {
        let log_data = BASE64.decode(log_data)
            .map_err(|_| DimLogError::InputError("Failed to decode base64 log data".to_string()))?;
        
        str::from_utf8(&log_data)
            .map(String::from)
            .map_err(|_| DimLogError::InputError("Failed to convert log data to string".to_string()))
    }

    fn split_log_line(line: &str) -> Result<Vec<String>, DimLogError> {
        // 1. 提取 log_type
        let start = line.rfind('[').ok_or_else(|| DimLogError::InputError("Invalid log format: missing log type".to_string()))?;
        let end = line.rfind(']').ok_or_else(|| DimLogError::InputError("Invalid log format: missing log type".to_string()))?;
        if end <= start {
            return Err(DimLogError::InputError("Invalid log format: bad log type".to_string()));
        }
        let log_type = line[start+1..end].trim().to_string();

        // 2. 去掉 log_type 部分，剩下的部分按空格分割
        let main_part = line[..start].trim();
        let mut iter = main_part.split_whitespace();

        // 3. 提取前三个固定字段
        let pcr_index = iter.next().ok_or_else(|| DimLogError::InputError("Missing PCR index".to_string()))?;
        let template_hash = iter.next().ok_or_else(|| DimLogError::InputError("Missing template hash".to_string()))?;
        let file_hash_part = iter.next().ok_or_else(|| DimLogError::InputError("Missing file hash".to_string()))?;

        // 4. 验证 file_hash_part 格式 (algorithm:hash)
        if !file_hash_part.contains(':') {
            return Err(DimLogError::InputError("Invalid file hash format: missing algorithm".to_string()));
        }

        // 5. 剩余部分作为 file_path
        let file_path = iter.collect::<Vec<&str>>().join(" ");
        if file_path.is_empty() {
            return Err(DimLogError::InputError("Missing file path".to_string()));
        }

        Ok(vec![
            pcr_index.to_string(),
            template_hash.to_string(),
            file_hash_part.to_string(),
            file_path,
            log_type,
        ])
    }

    pub fn parse_log_line(line: &str) -> Result<ParsedLogEntry, DimLogError> {
        let parts = Self::split_log_line(line)?;
        
        let pcr_index = Self::parse_pcr_index(&parts[0])?;
        let (hash_alg, file_hash) = Self::parse_hash_parts(&parts[2])?;

        // Validate template hash format using SHA256
        if !HashAlgorithm::Sha256.validate_hex_hash(&parts[1]) {
            return Err(DimLogError::ValidationError(
                format!("Invalid template hash format: expected {} hex characters", 
                    HashAlgorithm::Sha256.hex_length())
            ));
        }

        let log_entry = DimLogEntry {
            pcr_index,
            template_hash: parts[1].to_string(),
            file_hash_alg: hash_alg,
            file_hash,
            file_path: parts[3].to_string(),
            log_type: parts[4].to_string(),
            ref_value_matched: None,
        };

        Ok(ParsedLogEntry { pcr_index, log_entry })
    }

    pub(crate) fn parse_pcr_index(index_str: &str) -> Result<u32, DimLogError> {
        let pcr_index = index_str
            .parse::<u32>()
            .map_err(|_| DimLogError::InputError(
                format!("Invalid PCR index format: '{}'", index_str)
            ))?;

        if pcr_index > 23 {
            return Err(DimLogError::ValidationError(
                format!("PCR index {} is out of valid range (0-23)", pcr_index)
            ));
        }
        Ok(pcr_index)
    }

    pub(crate) fn parse_hash_parts(hash_str: &str) -> Result<(HashAlgorithm, String), DimLogError> {
        // File hash format: algorithm:hash
        let hash_parts: Vec<&str> = hash_str
            .split(':')
            .collect();

        if hash_parts.len() != 2 {
            return Err(DimLogError::InputError(
                format!("Invalid hash format: expected 'algorithm:hash', got '{}'", hash_str)
            ));
        }

        let alg = HashAlgorithm::from_str(hash_parts[0])?;
        let hash = hash_parts[1].to_string();

        // Validate hash format
        if !alg.validate_hex_hash(&hash) {
            return Err(DimLogError::ValidationError(
                format!("Invalid hash format for {}: expected {} hex characters", 
                    hash_parts[0], alg.hex_length())
            ));
        }

        Ok((alg, hash))
    }

    pub fn collect_file_hashes(&self) -> Result<Vec<String>, DimLogError> {
        let mut file_hashes = Vec::new();
        let mut seen_paths = HashSet::new();

        for entries in self.logs.values() {
            for log in entries {
                // Check for duplicate file paths
                if !seen_paths.insert(log.file_path.clone()) {
                    return Err(DimLogError::ValidationError(
                        format!("Duplicate file path found: {}", log.file_path)
                    ));
                }

                // Validate file hash
                if !log.file_hash_alg.validate_hex_hash(&log.file_hash) {
                    return Err(DimLogError::ValidationError(
                        format!("Invalid file hash format for {}: {}", log.file_path, log.file_hash)
                    ));
                }

                file_hashes.push(log.file_hash.clone());
            }
        }

        Ok(file_hashes)
    }

    async fn get_unmatched_hashes(
        &self,
        file_hashes: &Vec<String>,
        service_host_functions: &ServiceHostFunctions,
        user_id: &str
    ) -> Result<HashSet<String>, DimLogError> {
        if file_hashes.is_empty() {
            return Ok(HashSet::new());
        }
        let unmatched: Vec<String> = (service_host_functions.get_unmatched_measurements)(file_hashes, "tpm_dim", user_id)
            .await
            .map_err(|err| DimLogError::InternalError(format!("Failed to get unmatched measurements: {}", err)))?;
        Ok(unmatched.into_iter().collect())
    }

    fn update_ref_value_matches(&mut self, unmatched_hashes: &HashSet<String>) {
        for entries in self.logs.values_mut() {
            for entry in entries {
                entry.ref_value_matched = Some(!unmatched_hashes.contains(&entry.file_hash));
            }
        }
    }

    fn process_pcr_logs(
        &self,
        pcr_index: u32,
        logs: &[DimLogEntry],
        hash_alg: &str,
        pcr_values: &mut PcrValues
    ) -> Result<(), DimLogError> {
        // 计算所有条目的模板哈希，如果任何条目计算失败则返回错误
        let template_hashes: Vec<String> = logs
            .iter()
            .map(|log| {
                Self::calculate_template_hash(log, hash_alg)
                    .map_err(|e| DimLogError::ValidationError(format!(
                        "Failed to calculate template hash for PCR {}: {}", pcr_index, e
                    )))
            })
            .collect::<Result<Vec<String>, DimLogError>>()?;

        // 验证是否找到有效的模板哈希
        if template_hashes.is_empty() {
            return Err(DimLogError::ValidationError(
                format!("No log entries found for PCR {}", pcr_index)
            ));
        }

        // 获取初始 PCR 值
        let initial_value = PcrValues::create_initial_pcr_value(hash_alg, pcr_index, None)
            .map_err(|e| DimLogError::InternalError(e.to_string()))?;

        // 获取当前 PCR 值
        let pcr_value = pcr_values.get_pcr_value(pcr_index)
            .expect("PCR value should exist");

        // 重放 PCR 值
        let replay_value = PcrValues::replay_with_target(
            hash_alg,
            &initial_value,
            pcr_value,
            &template_hashes,
        ).map_err(|e| DimLogError::InternalError(e.to_string()))?;

        // 更新重放值
        pcr_values.update_replay_value(pcr_index, replay_value);
        Ok(())
    }

    pub(crate) fn calculate_template_hash(log: &DimLogEntry, hash_alg: &str) -> Result<String, DimLogError> {
        // 验证输入
        if log.file_hash.is_empty() {
            return Err(DimLogError::ValidationError("File hash cannot be empty".to_string()));
        }
        if log.file_path.is_empty() {
            return Err(DimLogError::ValidationError("File path cannot be empty".to_string()));
        }

        // 获取算法名称
        let algo_name = log.file_hash_alg.to_string();
        
        // 将 hex 格式的 file_hash 转换为二进制
        let file_hash_bytes = hex::decode(&log.file_hash)
            .map_err(|e| DimLogError::ValidationError(format!("Invalid file hash hex format: {}", e)))?;
        
        // 计算 size1: algo_name + ":" + "\0" + digest_size
        let size1 = (algo_name.len() + 2 + file_hash_bytes.len()) as u32;
        
        // 构建哈希输入
        let mut hasher = Hasher::new(HashAlgorithm::from_str(hash_alg)?.to_message_digest())
            .map_err(|e| DimLogError::InternalError(format!("Failed to create hasher: {}", e)))?;
        
        // 1. 添加 size1 (4字节小端序)
        hasher.update(&size1.to_le_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        
        // 2. 添加算法名称
        hasher.update(algo_name.as_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        
        // 3. 添加 ":" 和 "\0"
        hasher.update(b":\0")
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        
        // 4. 添加文件哈希（二进制）
        hasher.update(&file_hash_bytes)
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        
        // 5. 计算 size2: file_path + "\0"
        let size2 = (log.file_path.len() + 1) as u32;
        
        // 6. 添加 size2 (4字节小端序)
        hasher.update(&size2.to_le_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        
        // 7. 添加文件路径和 "\0"
        hasher.update(log.file_path.as_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        hasher.update(b"\0")
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        
        // 8. 完成哈希计算
        let hash = hasher.finish()
            .map_err(|e| DimLogError::InternalError(format!("Failed to finalize hash: {}", e)))?;
        
        Ok(hex::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm_common_verifier::PcrValues;

    #[test]
    fn test_verify_empty_log_pcrs() {
        // 测试空日志时的 PCR 验证
        let mut pcr_values = PcrValues::new();
        pcr_values.hash_alg = "sha256".to_string();
        
        // 设置所有 PCR 为初始值
        for i in 0..24 {
            let initial_value = PcrValues::create_initial_pcr_value("sha256", i, None).unwrap();
            pcr_values.set_pcr_value(i, initial_value);
        }
        
        // 验证空日志
        let dim_log = DimLog { logs: HashMap::new() };
        assert!(dim_log.replay_pcr_values(&mut pcr_values).is_ok());

        // 测试非初始值 PCR
        let non_initial_value = "1".repeat(64); // 非初始值
        pcr_values.set_pcr_value(0, non_initial_value);
        assert!(matches!(
            dim_log.replay_pcr_values(&mut pcr_values),
            Err(DimLogError::ValidationError(_))
        ));
    }

    #[test]
    fn test_process_pcr_logs_with_invalid_entries() {
        // 创建包含无效条目的日志
        let mut logs = HashMap::new();
        logs.insert(0, vec![
            DimLogEntry {
                pcr_index: 0,
                template_hash: "".to_string(), // 无效的模板哈希
                file_hash_alg: HashAlgorithm::Sha256,
                file_hash: "".to_string(), // 无效的文件哈希
                file_path: "".to_string(), // 无效的文件路径
                log_type: "static baseline".to_string(),
                ref_value_matched: None,
            }
        ]);

        let dim_log = DimLog { logs };
        let mut pcr_values = PcrValues::new();
        pcr_values.hash_alg = "sha256".to_string();
        let initial_value = PcrValues::create_initial_pcr_value("sha256", 0, None).unwrap();
        pcr_values.set_pcr_value(0, initial_value);

        // 验证处理无效条目时返回错误
        assert!(matches!(
            dim_log.replay_pcr_values(&mut pcr_values),
            Err(DimLogError::ValidationError(_))
        ));
    }

    #[test]
    fn test_pcr_replay_verification() {
        // 创建有效的日志条目
        let entry = DimLogEntry {
            pcr_index: 0,
            template_hash: "8ba44d557a9855c03bc243a8ba2d553347a52c1a322ea9cf8d3d1e0c8f0e2656".to_string(),
            file_hash_alg: HashAlgorithm::Sha256,
            file_hash: "5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02".to_string(),
            file_path: "test_file".to_string(),
            log_type: "static baseline".to_string(),
            ref_value_matched: None,
        };

        let mut logs = HashMap::new();
        logs.insert(0, vec![entry]);

        let dim_log = DimLog { logs };
        let mut pcr_values = PcrValues::new();
        pcr_values.hash_alg = "sha256".to_string();
        
        // 设置初始 PCR 值
        let initial_value = PcrValues::create_initial_pcr_value("sha256", 0, None).unwrap();
        pcr_values.set_pcr_value(0, initial_value);

        // 验证 PCR 重放
        assert!(dim_log.replay_pcr_values(&mut pcr_values).is_ok());
    }

    #[test]
    fn test_invalid_pcr_index() {
        let mut logs = HashMap::new();
        logs.insert(24, vec![DimLogEntry {
            pcr_index: 24, // 无效的 PCR 索引
            template_hash: "8ba44d557a9855c03bc243a8ba2d553347a52c1a322ea9cf8d3d1e0c8f0e2656".to_string(),
            file_hash_alg: HashAlgorithm::Sha256,
            file_hash: "5279eadc235d80bf66ba652b5d0a2c7afd253ebaf1d03e6e24b87b7f7e94fa02".to_string(),
            file_path: "test_file".to_string(),
            log_type: "static baseline".to_string(),
            ref_value_matched: None,
        }]);

        let dim_log = DimLog { logs };
        let mut pcr_values = PcrValues::new();
        pcr_values.hash_alg = "sha256".to_string();
        
        // 验证无效 PCR 索引返回错误
        assert!(matches!(
            dim_log.replay_pcr_values(&mut pcr_values),
            Err(DimLogError::ValidationError(_))
        ));
    }

    #[test]
    fn test_empty_hash_algorithm() {
        let mut pcr_values = PcrValues::new();
        pcr_values.hash_alg = "".to_string(); // 空哈希算法
        let dim_log = DimLog { logs: HashMap::new() };
        
        // 验证空哈希算法返回错误
        assert!(matches!(
            dim_log.replay_pcr_values(&mut pcr_values),
            Err(DimLogError::ValidationError(_))
        ));
    }
}
