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

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use openssl::hash::{Hasher, MessageDigest};
use plugin_manager::{PluginError, ServiceHostFunctions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::{self, FromStr};
use thiserror::Error;
use tpm_common_verifier::PcrValues;

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
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha384 => write!(f, "sha384"),
            Self::Sha512 => write!(f, "sha512"),
            Self::Sm3 => write!(f, "sm3"),
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
            logs.entry(entry.pcr_index).or_insert_with(Vec::new).push(entry.log_entry);
        }

        Ok(Self { logs })
    }

    /// Verify the DIM log against PCR values and reference measurements
    pub async fn verify(
        &mut self,
        pcr_values: &mut PcrValues,
        service_host_functions: &ServiceHostFunctions,
        user_id: &str,
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
        serde_json::to_value(self).map_err(|e| DimLogError::InternalError(e.to_string()))
    }

    /// Replay PCR values using the log entries
    pub fn replay_pcr_values(&self, pcr_values: &mut PcrValues) -> Result<(), DimLogError> {
        if self.logs.is_empty() {
            return Self::verify_empty_log_pcrs(pcr_values);
        }

        // Validate PCR indices
        self.validate_pcr_indices()?;

        // Process each PCR value
        for pcr_index in pcr_values.get_pcr_indices() {
            self.process_pcr_value(pcr_index, pcr_values)?;
        }

        Ok(())
    }

    /// Validate all PCR indices in the log
    fn validate_pcr_indices(&self) -> Result<(), DimLogError> {
        for &pcr_index in self.logs.keys() {
            if pcr_index > 23 {
                return Err(DimLogError::ValidationError(format!(
                    "PCR index {} is out of valid range (0-23)",
                    pcr_index
                )));
            }
        }
        Ok(())
    }

    /// Process a single PCR value
    fn process_pcr_value(&self, pcr_index: u32, pcr_values: &mut PcrValues) -> Result<(), DimLogError> {
        // Get current PCR value
        let pcr_value = match pcr_values.get_pcr_value(pcr_index) {
            Some(value) => value,
            None => return Ok(()),
        };

        // Check if we have logs for this PCR
        match self.logs.get(&pcr_index) {
            Some(logs) if !logs.is_empty() => {
                let logs_cloned = logs.clone();
                let hash_alg_str = pcr_values.hash_alg.clone();
                self.process_pcr_logs(pcr_index, &logs_cloned, &hash_alg_str, pcr_values)?;
            },
            _ => {
                // No logs found, verify PCR value is initial
                let initial_value = PcrValues::create_initial_pcr_value(&pcr_values.hash_alg, pcr_index, None)
                    .map_err(|e| DimLogError::InternalError(e.to_string()))?;

                if pcr_value != initial_value {
                    return Err(DimLogError::ValidationError(format!(
                        "PCR {} has been extended but no log entries found",
                        pcr_index
                    )));
                }
            },
        }
        Ok(())
    }

    /// Verify PCR values when log is empty
    fn verify_empty_log_pcrs(pcr_values: &PcrValues) -> Result<(), DimLogError> {
        if pcr_values.hash_alg.is_empty() {
            return Err(DimLogError::ValidationError("Hash algorithm cannot be empty".to_string()));
        }

        let hash_alg = &pcr_values.hash_alg;
        let mut non_initial_pcrs = Vec::new();

        for &pcr_index in &pcr_values.get_pcr_indices() {
            if pcr_index > 23 {
                return Err(DimLogError::ValidationError(format!(
                    "PCR index {} is out of valid range (0-23)",
                    pcr_index
                )));
            }

            let pcr_value = match pcr_values.get_pcr_value(pcr_index) {
                Some(v) => v,
                None => continue,
            };

            let initial_value = PcrValues::create_initial_pcr_value(hash_alg, pcr_index, None).map_err(|e| {
                DimLogError::InternalError(format!("Failed to create initial value for PCR {}: {}", pcr_index, e))
            })?;

            if pcr_value != initial_value {
                non_initial_pcrs.push(pcr_index);
            }
        }

        if !non_initial_pcrs.is_empty() {
            return Err(DimLogError::ValidationError(format!(
                "PCRs {:?} are not initial values but log is empty",
                non_initial_pcrs
            )));
        }

        Ok(())
    }

    /// Decode base64 log data
    fn decode_log_data(log_data: &str) -> Result<String, DimLogError> {
        let log_data = BASE64
            .decode(log_data)
            .map_err(|_| DimLogError::InputError("Failed to decode base64 log data".to_string()))?;

        str::from_utf8(&log_data)
            .map(String::from)
            .map_err(|_| DimLogError::InputError("Failed to convert log data to string".to_string()))
    }

    /// Split log line into components
    fn split_log_line(line: &str) -> Result<Vec<String>, DimLogError> {
        // Extract log type
        let (log_type, main_part) = Self::extract_log_type(line)?;

        // Split main part into components
        let mut iter = main_part.split_whitespace();
        let pcr_index = iter.next().ok_or_else(|| DimLogError::InputError("Missing PCR index".to_string()))?;
        let template_hash = iter.next().ok_or_else(|| DimLogError::InputError("Missing template hash".to_string()))?;
        let file_hash_part = iter.next().ok_or_else(|| DimLogError::InputError("Missing file hash".to_string()))?;

        // Validate file hash format
        if !file_hash_part.contains(':') {
            return Err(DimLogError::InputError("Invalid file hash format: missing algorithm".to_string()));
        }

        // Get file path
        let file_path = iter.collect::<Vec<&str>>().join(" ");
        if file_path.is_empty() {
            return Err(DimLogError::InputError("Missing file path".to_string()));
        }

        Ok(vec![pcr_index.to_string(), template_hash.to_string(), file_hash_part.to_string(), file_path, log_type])
    }

    /// Extract log type from line
    fn extract_log_type(line: &str) -> Result<(String, &str), DimLogError> {
        let start = line
            .rfind('[')
            .ok_or_else(|| DimLogError::InputError("Invalid log format: missing log type".to_string()))?;
        let end = line
            .rfind(']')
            .ok_or_else(|| DimLogError::InputError("Invalid log format: missing log type".to_string()))?;

        if end <= start {
            return Err(DimLogError::InputError("Invalid log format: bad log type".to_string()));
        }

        // Preserve the original log_type without modifying spaces
        let log_type = line[start + 1..end].trim().to_string();
        let main_part = line[..start].trim();

        Ok((log_type, main_part))
    }

    /// Parse a single log line
    pub fn parse_log_line(line: &str) -> Result<ParsedLogEntry, DimLogError> {
        let parts = Self::split_log_line(line)?;

        let pcr_index = Self::parse_pcr_index(&parts[0])?;
        let (hash_alg, file_hash) = Self::parse_hash_parts(&parts[2])?;

        // Validate template hash format
        if !HashAlgorithm::Sha256.validate_hex_hash(&parts[1]) {
            return Err(DimLogError::ValidationError(format!(
                "Invalid template hash format: expected {} hex characters",
                HashAlgorithm::Sha256.hex_length()
            )));
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

    /// Parse PCR index from string
    pub(crate) fn parse_pcr_index(index_str: &str) -> Result<u32, DimLogError> {
        let pcr_index = index_str
            .parse::<u32>()
            .map_err(|_| DimLogError::InputError(format!("Invalid PCR index format: '{}'", index_str)))?;

        if pcr_index > 23 {
            return Err(DimLogError::ValidationError(format!("PCR index {} is out of valid range (0-23)", pcr_index)));
        }
        Ok(pcr_index)
    }

    /// Parse hash algorithm and hash value from string
    pub(crate) fn parse_hash_parts(hash_str: &str) -> Result<(HashAlgorithm, String), DimLogError> {
        let hash_parts: Vec<&str> = hash_str.split(':').collect();

        if hash_parts.len() != 2 {
            return Err(DimLogError::InputError(format!(
                "Invalid hash format: expected 'algorithm:hash', got '{}'",
                hash_str
            )));
        }

        let alg = HashAlgorithm::from_str(hash_parts[0])?;
        let hash = hash_parts[1].to_string();

        if !alg.validate_hex_hash(&hash) {
            return Err(DimLogError::ValidationError(format!(
                "Invalid hash format for {}: expected {} hex characters",
                hash_parts[0],
                alg.hex_length()
            )));
        }

        Ok((alg, hash))
    }

    /// Collect all file hashes from the log
    pub fn collect_file_hashes(&self) -> Result<Vec<String>, DimLogError> {
        let mut file_hashes = Vec::new();
        let mut seen_paths = HashSet::new();

        for entries in self.logs.values() {
            for log in entries {
                if !seen_paths.insert(log.file_path.clone()) {
                    return Err(DimLogError::ValidationError(format!("Duplicate file path found: {}", log.file_path)));
                }

                if !log.file_hash_alg.validate_hex_hash(&log.file_hash) {
                    return Err(DimLogError::ValidationError(format!(
                        "Invalid file hash format for {}: {}",
                        log.file_path, log.file_hash
                    )));
                }

                file_hashes.push(log.file_hash.clone());
            }
        }

        Ok(file_hashes)
    }

    /// Get unmatched hashes from service
    async fn get_unmatched_hashes(
        &self,
        file_hashes: &Vec<String>,
        service_host_functions: &ServiceHostFunctions,
        user_id: &str,
    ) -> Result<HashSet<String>, DimLogError> {
        if file_hashes.is_empty() {
            return Ok(HashSet::new());
        }

        let unmatched: Vec<String> =
            (service_host_functions.get_unmatched_measurements)(file_hashes, "tpm_dim", user_id)
                .await
                .map_err(|err| DimLogError::InternalError(format!("Failed to get unmatched measurements: {}", err)))?;

        Ok(unmatched.into_iter().collect())
    }

    /// Update reference value matches in log entries
    fn update_ref_value_matches(&mut self, unmatched_hashes: &HashSet<String>) {
        for entries in self.logs.values_mut() {
            for entry in entries {
                entry.ref_value_matched = Some(!unmatched_hashes.contains(&entry.file_hash));
            }
        }
    }

    /// Process PCR logs for a specific PCR index
    fn process_pcr_logs(
        &self,
        pcr_index: u32,
        logs: &[DimLogEntry],
        hash_alg: &str,
        pcr_values: &mut PcrValues,
    ) -> Result<(), DimLogError> {
        let template_hashes: Vec<String> = logs
            .iter()
            .map(|log| {
                Self::calculate_template_hash(log, hash_alg).map_err(|e| {
                    DimLogError::ValidationError(format!(
                        "Failed to calculate template hash for PCR {}: {}",
                        pcr_index, e
                    ))
                })
            })
            .collect::<Result<Vec<String>, DimLogError>>()?;

        if template_hashes.is_empty() {
            return Err(DimLogError::ValidationError(format!("No log entries found for PCR {}", pcr_index)));
        }

        let initial_value = PcrValues::create_initial_pcr_value(hash_alg, pcr_index, None)
            .map_err(|e| DimLogError::InternalError(e.to_string()))?;

        let pcr_value = pcr_values.get_pcr_value(pcr_index).expect("PCR value should exist");

        let replay_value = PcrValues::replay_with_target(hash_alg, &initial_value, pcr_value, &template_hashes)
            .map_err(|e| DimLogError::InternalError(e.to_string()))?;


        pcr_values.update_replay_value(pcr_index, replay_value);
        Ok(())
    }

    /// Calculate template hash for a log entry
    /// Matches the C implementation in DIM source code:
    /// template hash = hash(
    ///     "file hash algorithm string size + file digest size"
    ///     + "file hash algorithm string"
    ///     + "file digest"
    ///     + "file path string size"
    ///     + "file path"
    /// )
    pub fn calculate_template_hash(log: &DimLogEntry, hash_alg: &str) -> Result<String, DimLogError> {
        if log.file_hash.is_empty() {
            return Err(DimLogError::ValidationError("File hash cannot be empty".to_string()));
        }
        if log.file_path.is_empty() {
            return Err(DimLogError::ValidationError("File path cannot be empty".to_string()));
        }

        let algo_name = log.file_hash_alg.to_string();
        let file_hash_bytes = hex::decode(&log.file_hash)
            .map_err(|e| DimLogError::ValidationError(format!("Invalid file hash hex format: {}", e)))?;

        // Calculate size1: algorithm name length + ":" length + 1 + digest size
        let size1 = (algo_name.len() + 1 + 1 + file_hash_bytes.len()) as u32;

        let mut hasher = Hasher::new(HashAlgorithm::from_str(hash_alg)?.to_message_digest())
            .map_err(|e| DimLogError::InternalError(format!("Failed to create hasher: {}", e)))?;

        // Update hash with all components in order:
        // 1. size1 (little endian)
        hasher
            .update(&size1.to_le_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        // 2. algorithm name
        hasher
            .update(algo_name.as_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        // 3. ":" + "\0"
        hasher.update(b":\0").map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        // 4. file hash bytes
        hasher
            .update(&file_hash_bytes)
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;

        // Calculate size2: file path length + 1 (for "\0")
        let size2 = (log.file_path.len() + 1) as u32;
        // 5. size2 (little endian)
        hasher
            .update(&size2.to_le_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        // 6. file path + "\0"
        hasher
            .update(log.file_path.as_bytes())
            .map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;
        hasher.update(b"\0").map_err(|e| DimLogError::InternalError(format!("Failed to update hash: {}", e)))?;

        let hash =
            hasher.finish().map_err(|e| DimLogError::InternalError(format!("Failed to finalize hash: {}", e)))?;

        Ok(hex::encode(hash))
    }
}
