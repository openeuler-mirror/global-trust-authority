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

//! Event Log Parsing
//! Including event log type definitions, parsing, verification, replay, and serialization.
//!
//! This module implements the functionality for parsing, validating, and serializing TPM event logs.
//! Event logs contain various UEFI components and configuration data measured during system boot,
//! used to verify system boot integrity.
//!
//! Main features include:
//! - Parsing TCG format event logs
//! - Verifying PCR value calculations in the log
//! - Replaying logs to verify their integrity
//! - Serializing logs into readable formats
//!

use std::sync::Arc;
use std::sync::Mutex;
use serde_json::{Value, json};
// use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hex;
use openssl::hash::{Hasher, MessageDigest, DigestBytes};
use tpm_common_verifier::{PcrValues, AlgorithmId, CryptoVerifier};
use plugin_manager::PluginError;
use crate::byte_reader::ByteReader;
use crate::event::model::{
    EventType, TpmEventLog,
    TcgDigestAlgorithm, EventLogEntry,
    EvNoActionEvent,
    SCrtmVersionEvent,
    UefiPlatformFirmwareBlobEvent, UefiPlatformFirmwareBlobEvent2, UefiFirmwareBlobEvent,
    EvSeparatorEvent, EventBaseString, PCClientTaggedEvent,
    UefiGptDataEvent,
    UefiImageLoadEvent,
};
use crate::event::parser::{
    TcgDigestParse, TcgDigestParseV1, TcgDigestParseV2,
    parse_uefi_variable_data_event, parse_typed_event
};

/// TPM Event Log
///
/// Contains the complete set of TPM event log entries and related metadata
///
/// # Fields
/// * `event_number` - Number of events in the log, used internally to record count, not serialized
/// * `raw_data` - Hexadecimal representation of raw log data, used for parsing,
/// passed in when creating the EventLog object, used internally only, not serialized
/// * `event_log` - The parsed collection of event log entries, serialized in the final output
/// * `selected_digest_alg` - Selected digest algorithm, specified by the uploaded PCR selections,
/// used to select which algorithm digest to verify and select, used internally only, not serialized
/// * `locality` - TPM operation locality information, parsed from the first event and assigned to locality,
/// used internally only, not serialized
/// * `pcr_values` - Collection of PCR values, used for validating the EventLog, used internally only, not serialized
// #[derive(Debug)]
pub struct EventLog {
    pub event_number: u32,
    pub raw_data: String,
    pub event_log: Vec<EventLogEntry>,
    pub selected_digest_alg: String,
    pub locality: u8,
    pub pcr_values: Option<Arc<Mutex<PcrValues>>>,
}

impl EventLog {
    /// Create a new event log object
    ///
    /// # Parameters
    /// * `log_data` - Raw data string of the event log, Base64 encoded binary data
    ///
    /// # Returns
    /// * `EventLog` - Initialized event log object
    pub fn new(log_data: &str) -> Self {
        let event_log = Self {
            event_number: 0,
            raw_data: log_data.to_string(),
            event_log: vec![],
            selected_digest_alg: String::new(),
            locality: 0,
            pcr_values: None,
        };
        event_log
    }

    /// Set the digest algorithm string from PCR selections, used to select which algorithm digest to verify and select
    ///
    /// # Parameters
    /// * `algorithm` - Digest algorithm string, e.g. "sha256"
    ///
    /// # Returns
    /// * `&mut Self` - Returns a self reference to support chained calls
    pub fn with_algorithm(&mut self, algorithm: &str) -> &mut Self {
        self.selected_digest_alg = algorithm.to_string();
        self
    }

    /// Set PCR values, used for validating the EventLog, will be output and serialized to JSON
    ///
    /// # Parameters
    /// * `pcr_values` - Thread-safe reference to PCR values
    ///
    /// # Returns
    /// * `&mut Self` - Returns a self reference to support chained calls
    pub fn with_pcr_values(&mut self, pcr_values: Arc<Mutex<PcrValues>>) -> &mut Self {
        self.pcr_values = Some(pcr_values);
        self
    }

    /// Parse event log
    ///
    /// Parses the original Base64 encoded event log data into a structured collection of event log entries
    ///
    /// # Returns
    /// * `Result<&mut Self, PluginError>` - Returns self reference on success, error on failure
    ///
    /// # Errors
    /// * Returns corresponding PluginError when Base64 decoding fails or errors occur during parsing
    pub fn parse_event_log(&mut self) -> Result<&mut Self, PluginError> {
        let event_data: Vec<u8> = BASE64.decode(self.raw_data.as_bytes())
            .map_err(|e| PluginError::InputError(format!("Failed to decode event log: {}", e)))?;

        let mut parser = ByteReader::new(&event_data);
        let mut event_log = Vec::new();

        let first_entry: EventLogEntry = self.parse_first_event(&mut parser)?;
        event_log.push(first_entry);
        self.event_number += 1;

        let digest_parser = TcgDigestParseV2;
        while parser.position() < parser.get_length() {
            let entry = self.parse_event_entry(&mut parser, &digest_parser)?;
            event_log.push(entry);
            self.event_number += 1;
        }

        self.event_log = event_log;
        Ok(self)
    }

    /// Parse the first event entry
    ///
    /// The first event typically uses TCG 1.2 format and requires special handling,
    /// differentiated by using TcgDigestParseV1
    ///
    /// # Parameters
    /// * `parser` - Byte reader
    ///
    /// # Returns
    /// * `Result<EventLogEntry, PluginError>` - Parsed event entry or error
    fn parse_first_event(&self, parser: &mut ByteReader) -> Result<EventLogEntry, PluginError> {
        let first_entry: EventLogEntry = self.parse_event_entry(parser, &TcgDigestParseV1)?;
        Ok(first_entry)
    }

    /// Parse a single event entry
    ///
    /// Parse a single event entry, including PCR index, event type, digest, and event data,
    /// with digest verification for certain events.
    /// The current module design does not support TCG 1.2 version event parsing, only TCG 2.0 version.
    /// Please note the usage scenario.
    ///
    /// # Parameters
    /// * `parser` - Byte reader
    /// * `digest_parser` - Digest parser
    ///
    /// # Returns
    /// * `Result<EventLogEntry, PluginError>` - Parsed event entry or error
    fn parse_event_entry(
        &self,
        parser: &mut ByteReader,
        digest_parser: &dyn TcgDigestParse,
    ) -> Result<EventLogEntry, PluginError> {
        // 1. Read PCR index
        let pcr_index: u32 = parser.read_u32()
            .map_err(|e| PluginError::InputError(
                format!("Failed to read PCR index: {}, event_number: {}", e, self.event_number)
            ))?;

        // 2. Read event type
        let event_type_raw: u32 = parser.read_u32()
            .map_err(|e| PluginError::InputError(
                format!("Failed to read event type: {}, event_number: {}", e, self.event_number)
            ))?;

        // Convert raw event type value to event type enum
        // Note: If the event type is not defined in the new specification (event_type_raw does not match in from_u32),
        // unwrap_or will return EventType::Unknown, ensuring parsing can continue
        // This design can handle new event types added in future TCG specification updates,
        // preventing parsing failure due to unrecognized event types
        let event_type: EventType = EventType::from_u32(event_type_raw)
            .unwrap_or(EventType::Unknown);

        // 3. Read digest
        let digest: TcgDigestAlgorithm = digest_parser.parse_digest(parser)
            .map_err(|e| PluginError::InputError(
                format!("Failed to parse digest: {}, event_number: {}, event_type: {}",
                    e, self.event_number, event_type)
            ))?;

        // 4. Read event size
        let event_size: u32 = parser.read_u32()
            .map_err(|e| PluginError::InputError(
                format!("Failed to read event size: {}, event_number: {}, event_type: {}",
                    e, self.event_number, event_type)
            ))?;
        // Sanity check: event size should not exceed remaining data
        if event_size as u64 > parser.remaining() {
            return Err(PluginError::InputError(
                format!("Event size {} exceeds remaining data {}, event_number: {}, event_type: {}",
                    event_size, parser.remaining(), self.event_number, event_type)
            ));
        }
        // 5. Read event data
        let event_data: Vec<u8> = parser.read_bytes(event_size as usize)
            .map_err(|e| PluginError::InputError(
                format!("Failed to read event data: {}, event_number: {}, event_type: {}",
                    e, self.event_number, event_type)
            ))?;

        // 6. Verify digest
        /*
            todo:
            - Need to determine whether to verify digest based on event_type,
            currently only verifying EvEfiVariableDriverConfig and EvEfiVariableAuthority
        */
        if digest_parser.is_v2() {
            if event_type.requires_digest_verification() {
                self.verify_digest(&digest, &event_data)
                    .map_err(|e| PluginError::InputError(
                        format!("Failed to verify digest: {}, event_number: {}, event_type: {}",
                            e, self.event_number, event_type)
                    ))?;
            }
        }

        // 6. Parse event data
        let event: TpmEventLog = Self::parse_event_data(&event_type, &event_data)
            .map_err(|e| PluginError::InputError(
                format!("Failed to parse event data: {}, event_number: {}, event_type: {}",
                    e, self.event_number, event_type)
            ))?;

        Ok(EventLogEntry {
            event_number: self.event_number,
            pcr_index,
            event_type,
            digest,
            event,
        })
    }

    /// Verify digest
    ///
    /// Verifies that the digest of event data matches the provided digest value
    ///
    /// # Parameters
    /// * `digest` - The digest to verify against
    /// * `data` - The data to calculate digest from
    ///
    /// # Returns
    /// * `Result<bool, PluginError>` - True if verification succeeds, error otherwise
    fn verify_digest(&self, digest: &TcgDigestAlgorithm, data: &[u8]) -> Result<bool, PluginError> {
        // Cannot have both selected_digest_alg and pcr_values unset, at least one must be set
        let hash_alg_str = if !self.selected_digest_alg.is_empty() {
            self.selected_digest_alg.clone()
        } else if let Some(pcr) = self.pcr_values.as_ref() {
            pcr.lock()
               .map_err(|e| PluginError::InputError(format!("Failed to lock PCR values: {}", e)))?
               .hash_alg.clone()
        } else {
            return Err(PluginError::InputError("No digest algorithm specified".to_string()));
        };

        let hash_alg: MessageDigest = CryptoVerifier::hash_str_to_message_digest(hash_alg_str.as_str())
            .map_err(|e| PluginError::InputError(
                format!("Unsupported hash algorithm: {}, error: {}", hash_alg_str, e)
            ))?;

        let mut hasher: Hasher = Hasher::new(hash_alg)
            .map_err(|e| PluginError::InputError(format!("Failed to create hasher: {}", e)))?;

        hasher.update(data)
            .map_err(|e| PluginError::InputError(format!("Failed to update hasher: {}", e)))?;

        let computed_digest: DigestBytes = hasher.finish()
            .map_err(|e| PluginError::InputError(format!("Failed to finish hasher: {}", e)))?;

        let hash_alg_id: AlgorithmId = AlgorithmId::from_str(hash_alg_str.as_str())
            .map_err(|e| PluginError::InputError(format!("Failed to parse hash algorithm: {}", e)))?;

        let digest_value: String = digest.get_digest_value(hash_alg_id);
        if digest_value.is_empty() {
            return Err(PluginError::InputError("Digest value is empty".to_string()));
        }
        let computed_hex: String = hex::encode(&computed_digest);
        if computed_hex == digest_value {
            Ok(true)
        } else {
            Err(PluginError::InputError("Digest value is not matched".to_string()))
        }
    }

    /// Parse event data
    ///
    /// Parses the event data structure according to the event type. This function handles all known TPM event types
    /// and converts raw byte data into structured TpmEventLog objects. Event types are processed by functional groups,
    /// using the helper function parse_typed_event to uniformly handle most event types.
    ///
    /// # Parameters
    /// * `event_type` - Event type, determines how to parse the event data
    /// * `event_data` - Raw event data byte array
    ///
    /// # Returns
    /// * `Result<TpmEventLog, PluginError>` - Returns the parsed event object on success, error on failure
    ///
    /// # Errors
    /// * Returns PluginError::InputError with detailed error information when errors occur during parsing
    ///
    /// # Implementation Details
    /// This function categorizes events into 9 main categories based on event type:
    /// 1. Firmware-related event group (e.g., EvPostCode)
    /// 2. Platform firmware event group (e.g., EvEfiPlatformFirmwareBlob)
    /// 3. Control event group (e.g., EvNoAction, EvSeparator)
    /// 4. String event group (e.g., EvAction)
    /// 5. Version and tag event group (e.g., EvEventTag, EvSCrtmVersion)
    /// 6. UEFI variable event group (requires special handling)
    /// 7. GPT event group
    /// 8. Boot services event group
    /// 9. Unknown event types (processed as raw data)
    fn parse_event_data(event_type: &EventType, event_data: &[u8]) -> Result<TpmEventLog, PluginError> {
        let mut parser = ByteReader::new(event_data);

        // Return appropriate parsing results based on event type
        match event_type {
            // 1. Firmware-related event group
            EventType::EvPostCode | EventType::EvPostCode2 | EventType::EvSCrtmContents => {
                parse_typed_event::<UefiFirmwareBlobEvent, _>(&mut parser, TpmEventLog::EventEfiFirmwareBlob,
                    "Firmware Blob Event"
                )
            },

            // 2. Platform firmware event group
            EventType::EvEfiPlatformFirmwareBlob => {
                parse_typed_event::<UefiPlatformFirmwareBlobEvent, _>(
                    &mut parser,
                    TpmEventLog::EventUefiPlatformFirmwareBlob,
                    "UEFI Platform Firmware Blob Event"
                )
            },
            EventType::EvEfiPlatformFirmwareBlob2 => {
                parse_typed_event::<UefiPlatformFirmwareBlobEvent2, _>(
                    &mut parser,
                    TpmEventLog::EventUefiPlatformFirmwareBlob2,
                    "UEFI Platform Firmware Blob2 Event"
                )
            },

            // 3. Control event group
            EventType::EvNoAction => {
                parse_typed_event::<EvNoActionEvent, _>(
                    &mut parser,
                    TpmEventLog::EventNoAction,
                    "No Action Event"
                )
            },
            EventType::EvSeparator => {
                parse_typed_event::<EvSeparatorEvent, _>(
                    &mut parser,
                    TpmEventLog::EventSeparator,
                    "Separator Event"
                )
            },

            // 4. String event group
            EventType::EvAction | EventType::EvOmitBootDeviceEvents |
            EventType::EvEfiAction | EventType::EvIpl | EventType::EvEfiHcrtmEvent => {
                parse_typed_event::<EventBaseString, _>(
                    &mut parser,
                    TpmEventLog::EventBaseStr,
                    "Base String Event"
                )
            },

            // 5. Version and tag event group
            EventType::EvEventTag => {
                parse_typed_event::<PCClientTaggedEvent, _>(
                    &mut parser,
                    TpmEventLog::EventPCClientTagged,
                    "PC Client Tagged Event"
                )
            },
            EventType::EvSCrtmVersion => {
                parse_typed_event::<SCrtmVersionEvent, _>(
                    &mut parser,
                    TpmEventLog::EventSCrtmVersion,
                    "S-CRTM Version Event"
                )
            },

            // 6. UEFI variable event group - uses specialized parser
            EventType::EvEfiVariableDriverConfig | EventType::EvEfiVariableBoot |
            EventType::EvEfiVariableBoot2 | EventType::EvEfiVariableAuthority |
            EventType::EvEfiSpdmDevicePolicy | EventType::EvEfiSpdmDeviceAuthority => {
                // This event type requires special handling, not using the generic helper function
                parse_uefi_variable_data_event(event_type, &mut parser)
                    .map(TpmEventLog::EventUefiVariable)
                    .map_err(|e| PluginError::InputError(format!("Failed to parse UEFI variable event: {}", e)))
            },

            // 7. GPT event group
            EventType::EvEfiGptEvent | EventType::EvEfiGptEvent2 => {
                parse_typed_event::<UefiGptDataEvent, _>(
                    &mut parser,
                    TpmEventLog::EventEfiGptEvent,
                    "UEFI GPT Event"
                )
            },

            // 8. Boot services event group
            EventType::EvEfiBootServicesApplication | EventType::EvEfiBootServicesDriver |
            EventType::EvEfiRuntimeServicesDriver => {
                parse_typed_event::<UefiImageLoadEvent, _>(
                    &mut parser,
                    TpmEventLog::EventEfiBootServicesApplication,
                    "UEFI Boot Services Application Event"
                )
            },

            // 9. other event types, processed as raw data
            // Handle unknown event types (including EventType::Unknown and other types not explicitly handled)
            // Here we save the data of unknown event types as raw binary data (Vec<u8>) in the EventBase variant
            // Preserving the raw data allows future versions of the parser to potentially correctly parse
            // these unknown types.
            // If hex string representation is needed, code conversion can be added here:
            // let hex_str = hex::encode(&data);
            // return Ok(TpmEventLog::EventHexString(hex_str));
            _ => {
                parser.read_bytes(parser.remaining() as usize)
                    .map(TpmEventLog::EventBase)
                    .map_err(|e| PluginError::InputError(
                        format!("Failed to read raw data for unknown event type: {}", e)
                    ))
            }
        }
    }

    /// Replay event log
    ///
    /// Replays all events in the log to verify PCR values match expected values
    ///
    /// # Returns
    /// * `Result<&mut Self, PluginError>` - Self reference or error
    ///
    /// # Errors
    /// * Returns `PluginError::InputError` if the selected digest algorithm is invalid,
    ///   if PCR values are not set, if locking PCR values fails, if getting a digest
    ///   value for an event fails, or if any error occurs during the replay calculation
    ///   for an individual event.
    pub fn replay(&mut self) -> Result<&mut Self, PluginError> {
        let hash_alg: AlgorithmId = AlgorithmId::from_str(self.selected_digest_alg.as_str())
            .map_err(|e| PluginError::InputError(format!("Failed to parse hash algorithm: {}", e)))?;

        for event in self.event_log.iter() {
            if event.event_type == EventType::EvNoAction {
                if let TpmEventLog::EventNoAction(EvNoActionEvent::StartupLocality(locality_event)) = &event.event {
                    self.locality = locality_event.locality;
                }
                continue;
            }

            let digest: String = event.digest.get_digest_value(hash_alg);
            if digest.is_empty() {
                return Err(PluginError::InputError(format!("Failed to get digest value: {}", event.event_type)));
            }
            self.replay_in_pcr_index(event.pcr_index, digest)
                .map_err(|e| PluginError::InputError(
                    format!("Failed to replay event {} for PCR {}: {}", event.event_number, event.pcr_index, e)
                ))?;
        }

        Ok(self)
    }

    /// Replay in PCR index
    ///
    /// Replays a single event in the specified PCR index by extending the PCR value with the digest
    ///
    /// # Parameters
    /// * `index` - PCR index to extend
    /// * `value` - Digest value to extend with
    ///
    /// # Returns
    /// * `Result<(), PluginError>` - Success or error
    fn replay_in_pcr_index(&self, index: u32, value: String) -> Result<(), PluginError> {
        // 1. Get digest algorithm and length
        let digest_len = AlgorithmId::from_str(&self.selected_digest_alg)
            .map_err(|e| PluginError::InputError(format!("Invalid digest algorithm: {}", e)))?
            .digest_size() as usize;

        // 2. Get PCR values reference and lock
        let mut pcr_values = self.pcr_values
            .as_ref()
            .ok_or_else(|| PluginError::InputError("PCR values not set".to_string()))?
            .lock()
            .map_err(|e| PluginError::InputError(format!("Failed to lock PCR values: {}", e)))?;

        // 3. Get last replay value
        let last_value = pcr_values.get_pcr_replay_value(index)?;

        // 4. Determine initial value - use function to generate initial value
        let initial_value = match last_value.as_deref() {
            Some(val) if !val.is_empty() => val.to_string(),
            _ => tpm_common_verifier::PcrValues::create_initial_pcr_value(&self.selected_digest_alg, index, Some(self.locality)).unwrap()
        };

        // 5. Calculate replay value and update
        let replay_value = PcrValues::replay(
            &self.selected_digest_alg,
            &initial_value,
            &vec![value]
        )?;

        pcr_values.update_replay_value(index, replay_value);
        Ok(())
    }

    /// Verify PCR values
    ///
    /// Replays all events and verifies that calculated PCR values match expected values
    ///
    /// # Returns
    /// * `Result<bool, PluginError>` - True if verification succeeds, error otherwise
    ///
    /// # Errors
    /// * Returns `PluginError::InputError` if `replay()` fails, if PCR values are not set,
    ///   if locking PCR values fails, or if `check_is_matched()` fails (indicating PCR values do not match).
    pub fn verify(&mut self) -> Result<bool, PluginError> {
        self.replay()?;
        self.pcr_values
            .as_ref()
            .ok_or_else(|| PluginError::InputError("PCR values not set".to_string()))?
            .lock()
            .map_err(|e| PluginError::InputError(format!("Failed to lock PCR values: {}", e)))?
            .check_is_matched()
    }

    /// Convert to JSON value
    ///
    /// Converts the event log to a JSON value for serialization
    ///
    /// # Returns
    /// * `Result<Value, PluginError>` - JSON value or error
    ///
    /// # Errors
    /// * Returns `PluginError::InputError` if the `selected_digest_alg` is not found
    ///   in a TCG 2.0 digest entry, or if serialization of an event fails.
    pub fn to_json_value(&self) -> Result<Value, PluginError> {
        let event_entries = self.event_log.iter().map(|entry| {
            let mut obj = serde_json::Map::new();

            obj.insert("event_number".to_string(), json!(entry.event_number));
            obj.insert("pcr_index".to_string(), json!(entry.pcr_index));
            obj.insert("event_type".to_string(), json!(entry.event_type.to_string()));

            match &entry.digest {
                TcgDigestAlgorithm::V1(digest) => {
                    obj.insert("digest".to_string(), json!(digest));
                },
                TcgDigestAlgorithm::V2(entries) => {
                    if let Some(digest_entry) = entries.iter().find(|e|
                        e.algorithm_id.to_string().to_lowercase() == self.selected_digest_alg.to_lowercase()) {

                        let digest_obj = json!({
                            "hash_id": digest_entry.algorithm_id.to_string(),
                            "digest": digest_entry.digest_value
                        });

                        obj.insert("digest".to_string(), digest_obj);
                    } else {
                        return Err(PluginError::InputError(format!(
                            "Cannot find specified digest algorithm: {}, event number: {}",
                            self.selected_digest_alg, entry.event_number
                        )));
                    }
                }
            }

            match serde_json::to_value(&entry.event) {
                Ok(event_json) => {
                    obj.insert("event".to_string(), event_json);
                    Ok(Value::Object(obj))
                },
                Err(e) => Err(PluginError::InputError(format!("Failed to serialize event: {}", e)))
            }
        }).collect::<Result<Vec<Value>, PluginError>>()?;

        Ok(Value::Array(event_entries))
    }
}
