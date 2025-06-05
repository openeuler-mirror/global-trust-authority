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

//! Event Parsing Module
//!
//! This module implements parsing functionality for various event types in TPM event logs, including:
//! - TCG digest parsing
//! - EFI specific ID event parsing
//! - UEFI boot event parsing
//! - Firmware BLOB event parsing
//! - Variable data event parsing
//! - UEFI partition table parsing
//!
//! The module defines various implementations of the `ByteParseable` trait for parsing binary data into
//! specific event structures.
//! These parsers collectively support the complete boot integrity verification process.

use plugin_manager::PluginError;
use tpm_common_verifier::AlgorithmId;
use std::mem::size_of;
use hex;
use crate::byte_reader::{
    ByteReader, ByteParseable,
    UEFI_GUID_SIZE,
};
use crate::event::model::{
    EventType,
    NO_ACTION_EVENT_SIZE, UEFI_PARTITION_NAME_SIZE,
    SPEC_ID_EVENT_SIGNATURE_03, SPEC_ID_EVENT_SIGNATURE_00, STARTUP_LOCALITY_SIGNATURE,
    TpmDigestEntry, TcgDigestAlgorithm, TcgEfiSpecIdEventAlgorithmSize,
    EfiSpecIdEvent, StartupLocalityEvent, EvNoActionEvent,
    SCrtmVersionEvent,
    EfiSignatureList, EfiSignatureData, UefiVariableDataEvent, EfiVariableSecureBoot, EfiLoadOption, EfiVariableData,
    UefiPlatformFirmwareBlobEvent, UefiPlatformFirmwareBlobEvent2, UefiFirmwareBlobEvent,
    EvSeparatorEvent, EventBaseString, PCClientTaggedEvent,
    UefiPartitionHeader, UefiPartitionEntry, UefiGptDataEvent,
    UefiImageLoadEvent,
    TpmEventLog,
};

// SHA1 digest length in bytes
const SHA1_DIGEST_SIZE: usize = 20;
const TCG_DIGEST_ALGORITHM_COUNT: usize = 5; // sha1, sha256, sha384, sha512, sm3

const VAR_SECURE_BOOT: &str = "SecureBoot";
const VAR_DB: &str = "db";
const VAR_DBX: &str = "dbx";
const VAR_KEK: &str = "KEK";
const VAR_PK: &str = "PK";
const VAR_SBAT_LEVEL: &str = "SbatLevel";
const VAR_SHIM: &str = "shim";
const VAR_MOK_LIST_TRUSTED: &str = "MokListTrusted";
const VAR_BOOT_ORDER: &str = "BootOrder";
const VAR_BOOT_PREFIX: &str = "Boot";
// Boot entry name length, format is BootXXXX, total 8 characters
const VAR_BOOT_ENTRY_LENGTH: u64 = 8;
// Common values
const YES_STR: &str = "Yes";
const NO_STR: &str = "No";

/// Converts a boolean or 0/1 value to "Yes"/"No" string
///
/// # Parameters
/// * `value` - The boolean value to convert
///
/// # Returns
/// * Returns "Yes" for true, "No" for false
fn bool_to_yes_no(value: bool) -> String {
    if value {
        YES_STR.to_string()
    } else {
        NO_STR.to_string()
    }
}

/// TCG Digest Parsing Trait
///
/// Defines methods for parsing TCG digest algorithms. Different TCG specification versions
/// have different digest formats, and this trait provides a unified interface for handling
/// multiple versions.
pub trait TcgDigestParse {
    /// Parses digest data from a byte stream
    ///
    /// # Parameters
    /// * `cursor` - Byte reader containing the digest data
    ///
    /// # Returns
    /// * `Result<TcgDigestAlgorithm, PluginError>` - The parsed digest algorithm or an error
    /// 
    /// # Errors
    /// * `PluginError::InputError` - If there's an error reading the digest data
    fn parse_digest(&self, cursor: &mut ByteReader) -> Result<TcgDigestAlgorithm, PluginError>;

    /// Determines if this is a TCG 2.0 version
    ///
    /// # Returns
    /// * `bool` - Default returns false, indicating not a 2.0 version
    fn is_v2(&self) -> bool {
        false
    }
}

/// TCG 1.2 version digest parser
pub struct TcgDigestParseV1;

/// TCG 2.0 version digest parser
pub struct TcgDigestParseV2;

/// TCG 1.2 digest contains only a single digest field
impl TcgDigestParse for TcgDigestParseV1 {
    fn parse_digest(&self, cursor: &mut ByteReader) -> Result<TcgDigestAlgorithm, PluginError> {
        let digest: Vec<u8> = cursor.read_bytes(SHA1_DIGEST_SIZE)?;
        Ok(TcgDigestAlgorithm::V1(hex::encode(digest)))
    }
}

/// TCG 2.0 digest contains multiple digests, each with an algorithm ID and digest data
impl TcgDigestParse for TcgDigestParseV2 {
    fn parse_digest(&self, cursor: &mut ByteReader) -> Result<TcgDigestAlgorithm, PluginError> {
        let digest_count: u32 = cursor.read_u32()
        .map_err(|e| PluginError::InputError(format!("Failed to read digest count: {}", e)))?;

        if digest_count > TCG_DIGEST_ALGORITHM_COUNT as u32 {
            return Err(PluginError::InputError(format!("Invalid digest count: {}", digest_count)));
        }

        let mut digests: Vec<TpmDigestEntry> = Vec::with_capacity(digest_count as usize);
        for _ in 0..digest_count {
            let algorithm_id_raw: u16 = cursor.read_u16()
                .map_err(|e| PluginError::InputError(format!("Failed to read algorithm ID: {}", e)))?;
            let algorithm_id: AlgorithmId = AlgorithmId::from(algorithm_id_raw);

            let digest_size: usize = algorithm_id.digest_size() as usize;
            if digest_size == 0 {
                return Err(PluginError::InputError(format!("Invalid algorithm ID: {}", algorithm_id_raw)));
            }

            let digest_data: Vec<u8> = cursor.read_bytes(digest_size as usize)
                .map_err(|e| PluginError::InputError(format!("Failed to read digest data: {}", e)))?;

            digests.push(TpmDigestEntry::new(algorithm_id, hex::encode(digest_data)));
        }

        Ok(TcgDigestAlgorithm::V2(digests))
    }

    fn is_v2(&self) -> bool {
        true
    }
}

impl ByteParseable for EfiSpecIdEvent {
    /// Parses EFI specification ID event
    ///
    /// This event contains TCG specification version information and supported digest algorithms
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let platform_class: u32 = parser.read_u32()?;
        let family_minor: u8 = parser.read_u8()?;
        let family_major: u8 = parser.read_u8()?;
        let spec_version: u8 = parser.read_u8()?;
        let uintn_size: u8 = parser.read_u8()?;

        let algorithm_count: u32 = parser.read_u32()?;

        if algorithm_count > TCG_DIGEST_ALGORITHM_COUNT as u32 {
            return Err(PluginError::InputError(format!("Invalid algorithm count: {}", algorithm_count)));
        }

        let mut digest_algorithms: Vec<TcgEfiSpecIdEventAlgorithmSize> = Vec::with_capacity(algorithm_count as usize);
        for _ in 0..algorithm_count {
            let algorithm_id: u16 = parser.read_u16()?;
            let digest_size: u16 = parser.read_u16()?;
            digest_algorithms.push(TcgEfiSpecIdEventAlgorithmSize::new(algorithm_id, digest_size));
        }

        let vendor_info_size: u8 = parser.read_u8()?;
        let vendor_info: Vec<u8> = {
            if vendor_info_size > 0 {
                parser.read_bytes(vendor_info_size as usize)?
            } else {
                vec![]
            }
        };

        Ok(EfiSpecIdEvent {
            signature: String::from_utf8_lossy(SPEC_ID_EVENT_SIGNATURE_03).trim_end_matches('\0').to_string(),
            platform_class,
            family_minor,
            family_major,
            spec_version,
            uintn_size,
            algorithm_count: algorithm_count as usize,
            digest_algorithms,
            vendor_info_size,
            vendor_info,
        })
    }
}

impl ByteParseable for StartupLocalityEvent {
    /// Parses startup locality event
    ///
    /// This event contains TPM startup locality information
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let locality: u8 = parser.read_u8()?;
        Ok(StartupLocalityEvent {
            signature: String::from_utf8_lossy(STARTUP_LOCALITY_SIGNATURE).trim_end_matches('\0').to_string(),
            locality,
        })
    }
}

impl ByteParseable for EvNoActionEvent {
    /// Parses no action event
    ///
    /// Parses into different no action event types based on signature
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let signature: Vec<u8> = parser.read_bytes(NO_ACTION_EVENT_SIZE)?;
        if signature == SPEC_ID_EVENT_SIGNATURE_00 {
            Err(PluginError::InputError("Not support spec id event.".to_string()))
        } else if signature == SPEC_ID_EVENT_SIGNATURE_03 {
            let event: EfiSpecIdEvent = EfiSpecIdEvent::parse_from(parser)?;
            Ok(EvNoActionEvent::SpecIdEvent(event))
        } else if signature == STARTUP_LOCALITY_SIGNATURE {
            let event: StartupLocalityEvent = StartupLocalityEvent::parse_from(parser)?;
            Ok(EvNoActionEvent::StartupLocality(event))
        } else {
            let unknown_data: Vec<u8> = parser.read_bytes(parser.remaining() as usize)?;
            Ok(EvNoActionEvent::Unknown(unknown_data))
        }
    }
}

impl ByteParseable for EvSeparatorEvent {
    /// Parses separator event
    ///
    /// Separator events are used to separate events from different stages
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let value: u32 = parser.read_u32()?;
        Ok(EvSeparatorEvent {value})
    }
}

impl ByteParseable for EventBaseString {
    /// Parses base string event
    ///
    /// Parses all remaining bytes as a UTF-8 string
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let value: Vec<u8> = parser.read_bytes(parser.remaining() as usize)?;
        Ok(EventBaseString { value: String::from_utf8_lossy(&value).to_string() })
    }
}

impl ByteParseable for PCClientTaggedEvent {
    /// Parses PC client tagged event
    ///
    /// Contains event ID, data size, and data content
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let tagged_event_id: u32 = parser.read_u32()?;
        let tagged_event_data_size: u32 = parser.read_u32()?;
        let tagged_event_data: Vec<u8> = parser.read_bytes(tagged_event_data_size as usize)?;
        Ok(PCClientTaggedEvent { tagged_event_id, tagged_event_data_size, tagged_event_data })
    }
}

impl ByteParseable for UefiPlatformFirmwareBlobEvent {
    /// Parses UEFI platform firmware BLOB event
    ///
    /// Contains firmware base address and length information
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let blob_base: u64 = parser.read_u64()?;
        let blob_length: u64 = parser.read_u64()?;
        Ok(UefiPlatformFirmwareBlobEvent {
            blob_base,
            blob_length,
        })
    }
}

impl ByteParseable for UefiPlatformFirmwareBlobEvent2 {
    /// Parses UEFI platform firmware BLOB event (version 2)
    ///
    /// Compared to version 1, adds a description field
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let blob_description_size: u8 = parser.read_u8()?;
        let blob_description: Vec<u8> = parser.read_bytes(blob_description_size as usize)?;
        let blob_base: u64 = parser.read_u64()?;
        let blob_length: u64 = parser.read_u64()?;
        Ok(UefiPlatformFirmwareBlobEvent2 {
            blob_description: String::from_utf8_lossy(&blob_description).to_string(),
            blob_base,
            blob_length,
        })
    }
}

impl ByteParseable for UefiFirmwareBlobEvent {
    /// Parses UEFI firmware BLOB event
    ///
    /// May be one of multiple formats: version 1, version 2, or string
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        // If remaining bytes can't even form UefiPlatformFirmwareBlobEvent (16 bytes), treat as string
        if parser.remaining() < size_of::<UefiPlatformFirmwareBlobEvent>() as u64 {
            let data: Vec<u8> = parser.read_bytes(parser.remaining() as usize)?;
            return Ok(UefiFirmwareBlobEvent::UefiPlatformFirmwareString(String::from_utf8_lossy(&data).to_string()));
        }

        // First check if it matches the size of UefiPlatformFirmwareBlobEvent (no description field)
        if parser.remaining() as usize == size_of::<UefiPlatformFirmwareBlobEvent>() {
            let event: UefiPlatformFirmwareBlobEvent = UefiPlatformFirmwareBlobEvent::parse_from(parser)?;
            return Ok(UefiFirmwareBlobEvent::UefiPlatformFirmwareBlob(event));
        }

        // Save position to restore it after reading the description size
        let start_position = parser.position();

        // Try to read the blob_description_size for UefiPlatformFirmwareBlobEvent2
        let blob_description_size = parser.read_u8()? as usize;

        // Calculate expected size for UefiPlatformFirmwareBlobEvent2
        // sizeof(u8) + blob_description_size + sizeof(u64) + sizeof(u64)
        let expected_size = size_of::<u8>() + blob_description_size + size_of::<u64>() * 2;

        // Reset position for full parsing
        parser.set_position(start_position)?;

        // If the remaining bytes match the expected size for UefiPlatformFirmwareBlobEvent2
        if parser.remaining() as usize == expected_size {
            let event: UefiPlatformFirmwareBlobEvent2 = UefiPlatformFirmwareBlobEvent2::parse_from(parser)?;
            Ok(UefiFirmwareBlobEvent::UefiPlatformFirmwareBlob2(event))
        } else {
            // If none of the known structures match, treat as string
            let data: Vec<u8> = parser.read_bytes(parser.remaining() as usize)?;
            Ok(UefiFirmwareBlobEvent::UefiPlatformFirmwareString(String::from_utf8_lossy(&data).to_string()))
        }
    }
}

impl ByteParseable for SCrtmVersionEvent {
    /// Parses S-CRTM version event
    ///
    /// May be a GUID or UCS-2 string
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        // Check if it's a 16-byte GUID
        if parser.remaining() as usize == UEFI_GUID_SIZE {
            let guid_str: String = parser.read_guid()?;
            Ok(SCrtmVersionEvent { version: guid_str })
        } else {
            // Parse as UCS-2 string
            let unicode_str = parser.read_ucs2_string()?;
            Ok(SCrtmVersionEvent { version: unicode_str })
        }
    }
}

impl ByteParseable for EfiSignatureData {
    /// Parses EFI signature data
    ///
    /// Contains signature owner GUID and signature data
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let signature_owner: String = parser.read_guid()?;
        let signature_data: Vec<u8> = parser.read_bytes(parser.remaining() as usize)?;
        Ok(EfiSignatureData { 
            signature_owner,
            signature_data: hex::encode(signature_data)
        })
    }
}

impl ByteParseable for EfiVariableSecureBoot {
    /// Parses EFI secure boot variable
    ///
    /// Reads enabled status (1=enabled, 0=disabled)
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let enabled: u8 = parser.read_u8()?;
        Ok(EfiVariableSecureBoot { enabled: bool_to_yes_no(enabled == 1) })
    }
}

impl ByteParseable for EfiSignatureList {
    /// Parses EFI signature list
    ///
    /// Contains signature type, list size, header size, signature size, and multiple signature data
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        // signature type is guid.
        let signature_type: String = parser.read_guid()?;

        let signature_list_size: u32 = parser.read_u32()?;
        let signature_header_size: u32 = parser.read_u32()?;
        let signature_size: u32 = parser.read_u32()?;
        let signature_header: Vec<u8> = parser.read_bytes(signature_header_size as usize)?;

        // guid + list size（4 bytes） + header size(4 bytes) + sign size(4 bytes) + sign header size
        let prefix_size = UEFI_GUID_SIZE + size_of::<u32>() * 3 + signature_header_size as usize;
        if signature_list_size as usize <= prefix_size || signature_size == 0 {
            return Err(PluginError::InputError("Invalid signature list size or signature size".to_string()));
        }

        let signature_count = (signature_list_size as usize - prefix_size) / signature_size as usize;
        let mut signatures: Vec<EfiSignatureData> = Vec::with_capacity(signature_count);

        for _ in 0..signature_count {
            let signature_owner: String = parser.read_guid()?;
            let signature_data_size = signature_size as usize - UEFI_GUID_SIZE;
            let signature_data: Vec<u8> = parser.read_bytes(signature_data_size)?;
            signatures.push(EfiSignatureData {
                signature_owner,
                signature_data: hex::encode(signature_data),
            });
        }

        Ok(EfiSignatureList {
            signature_type,
            signature_list_size,
            signature_header_size,
            signature_size,
            signature_header,
            signatures,
        })
    }
}

impl ByteParseable for EfiLoadOption {
    /// Parses EFI load option
    ///
    /// Contains attributes, file path list length, description, and device path
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let attributes: u32 = parser.read_u32()?;
        let file_path_list_length: u16 = parser.read_u16()?;
        let description: String = parser.read_unicode_name(file_path_list_length as usize / 2)?;
        let device_path: Vec<u8> = parser.read_bytes(parser.remaining() as usize)?;
        Ok(EfiLoadOption {
            attributes: bool_to_yes_no(attributes == 1),
            file_path_list_length,
            description,
            device_path
        })
    }
}

/// Parses UEFI variable data event
///
/// # Parameters
/// * `event_type` - Event type that determines how to parse variable data
/// * `parser` - Byte reader containing the data to parse
///
/// # Returns
/// * `Result<UefiVariableDataEvent, PluginError>` - Parsed variable data event or error
///
/// # Description
/// This function parses different types of UEFI variable data based on event type and variable name.
/// Supported variable types include:
/// - Secure boot status (SecureBoot)
/// - Signature databases (db, dbx, KEK, PK)
/// - SBAT level
/// - MOK list
/// - Boot order and boot entries
/// 
/// # Errors
/// * `PluginError::InputError` - If input data is invalid or cannot be parsed
pub fn parse_uefi_variable_data_event(
    event_type: &EventType,
    parser: &mut ByteReader
) -> Result<UefiVariableDataEvent, PluginError> {
    // read guid
    let guid: String = parser.read_guid()?;

    // read unicode name length, length in char16.
    let unicode_name_length: u64 = parser.read_u64()?;

    // read variable data length, size in bytes.
    let variable_data_length: u64 = parser.read_u64()?;

    let unicode_name: String = parser.read_unicode_name(unicode_name_length as usize)?;

    let variable_data = match event_type {
        EventType::EvEfiVariableDriverConfig => {
            match unicode_name.as_str() {
                VAR_DB | VAR_DBX | VAR_KEK | VAR_PK if unicode_name_length == unicode_name.len() as u64 => {
                    let mut signature_list = Vec::new();
                    while !parser.is_end() {
                        signature_list.push(EfiSignatureList::parse_from(parser)?);
                    }
                    EfiVariableData::SignatureList(signature_list)
                },
                VAR_SECURE_BOOT if unicode_name_length == VAR_SECURE_BOOT.len() as u64 => {
                    let secure_boot = EfiVariableSecureBoot::parse_from(parser)?;
                    EfiVariableData::SecureBoot(secure_boot)
                },
                _ => {
                    let data = parser.read_bytes(parser.remaining() as usize)?;
                    EfiVariableData::Unknown(hex::encode(data))
                }
            }
        },
        EventType::EvEfiVariableAuthority => {
            match unicode_name.as_str() {
                VAR_SBAT_LEVEL if unicode_name_length == VAR_SBAT_LEVEL.len() as u64 => {
                    let variable_data = EventBaseString::parse_from(parser)?;
                    EfiVariableData::VariableAuthority(variable_data)
                },
                VAR_DB | VAR_SHIM if unicode_name_length == unicode_name.len() as u64 => {
                    let variable_data = EfiSignatureList::parse_from(parser)?;
                    EfiVariableData::AuthoritySignatureList(variable_data)
                },
                VAR_MOK_LIST_TRUSTED if unicode_name_length == VAR_MOK_LIST_TRUSTED.len() as u64 => {
                    let secure_boot = EfiVariableSecureBoot::parse_from(parser)?;
                    EfiVariableData::SecureBoot(secure_boot)
                },
                _ => {
                    let data = parser.read_bytes(parser.remaining() as usize)?;
                    EfiVariableData::Unknown(hex::encode(data))
                }
            }
        },
        EventType::EvEfiVariableBoot | EventType::EvEfiVariableBoot2 => {
            match  unicode_name.as_str() {
                VAR_BOOT_ORDER if unicode_name_length == VAR_BOOT_ORDER.len() as u64 => {
                    let boot_order_count: u64 = variable_data_length / 2; // Each boot order entry is 2 bytes (u16)
                    let mut boot_order = Vec::with_capacity(boot_order_count as usize);
                    for _ in 0..boot_order_count {
                        let boot_order_item: u16 = parser.read_u16()?;
                        boot_order.push(VAR_BOOT_PREFIX.to_string() + &format!("{:04X}", boot_order_item));
                    }
                    EfiVariableData::BootOrder(boot_order)
                },
                VAR_BOOT_PREFIX if unicode_name_length == VAR_BOOT_ENTRY_LENGTH => {
                    let boot = EfiLoadOption::parse_from(parser)?;
                    EfiVariableData::Boot(boot)
                },
                _=> {
                    let data = parser.read_bytes(parser.remaining() as usize)?;
                    EfiVariableData::Unknown(hex::encode(data))
                }
            }
        },
        _ => {
            let data = parser.read_bytes(parser.remaining() as usize)?;
            EfiVariableData::Unknown(hex::encode(data))
        }
    };

    Ok(UefiVariableDataEvent {
        variable_name: guid,
        unicode_name,
        variable_data,
    })
}

impl ByteParseable for UefiPartitionHeader {
    /// Parses UEFI partition header
    ///
    /// Contains various metadata for the partition table
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let signature: String = parser.read_string(size_of::<u64>() as usize)?;
        let revision: u32 = parser.read_u32()?;
        let header_size: u32 = parser.read_u32()?;
        let header_crc32: u32 = parser.read_u32()?;
        let reserved: u32 = parser.read_u32()?;
        let my_lba: u64 = parser.read_u64()?;
        let alternate_lba: u64 = parser.read_u64()?;
        let first_usable_lba: u64 = parser.read_u64()?;
        let last_usable_lba: u64 = parser.read_u64()?;
        let disk_guid: String = parser.read_guid()?;
        let partition_entries_lba: u64 = parser.read_u64()?;
        let number_of_partition_entries: u32 = parser.read_u32()?;
        let size_of_partition_entry: u32 = parser.read_u32()?;
        let partition_entry_array_crc32: u32 = parser.read_u32()?;
        Ok(Self {
            signature,
            revision,
            header_size,
            header_crc32,
            reserved,
            my_lba,
            alternate_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid,
            partition_entries_lba,
            number_of_partition_entries,
            size_of_partition_entry,
            partition_entry_array_crc32,
        })
    }
}

impl ByteParseable for UefiPartitionEntry {
    /// Parses UEFI partition table entry
    ///
    /// Contains detailed information for a single partition
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let partition_type_guid: String = parser.read_guid()?;
        let unique_partition_guid: String = parser.read_guid()?;
        let starting_lba: u64 = parser.read_u64()?;
        let ending_lba: u64 = parser.read_u64()?;
        let attributes: u64 = parser.read_u64()?;
        let partition_name: String = parser.read_unicode_name(UEFI_PARTITION_NAME_SIZE / 2)?;
        Ok(Self {
            partition_type_guid,
            unique_partition_guid,
            starting_lba,
            ending_lba,
            attributes,
            partition_name,
        })
    }
}

impl ByteParseable for UefiGptDataEvent {
    /// Parses UEFI GPT data event
    ///
    /// Contains partition header and list of partition entries
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let uefi_partition_header: UefiPartitionHeader = UefiPartitionHeader::parse_from(parser)?;
        let number_of_partitions: u64 = parser.read_u64()?;
        let mut partitions: Vec<UefiPartitionEntry> = Vec::with_capacity(number_of_partitions as usize);
        for _ in 0..number_of_partitions {
            let partition: UefiPartitionEntry = UefiPartitionEntry::parse_from(parser)?;
            partitions.push(partition);
        }
        Ok(Self {
            uefi_partition_header,
            number_of_partitions,
            partitions,
        })
    }
}

impl ByteParseable for UefiImageLoadEvent {
    /// Parses UEFI image load event
    ///
    /// Contains image location, size, and device path information
    fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
        let image_location_in_memory: u64 = parser.read_u64()?;
        let image_length_in_memory: u64 = parser.read_u64()?;
        let image_link_time_address: u64 = parser.read_u64()?;
        let length_of_device_path: u64 = parser.read_u64()?;
        let device_path: Vec<u8> = parser.read_bytes(length_of_device_path as usize)?;
        Ok(Self {
            image_location_in_memory,
            image_length_in_memory,
            image_link_time_address,
            length_of_device_path,
            device_path: hex::encode(device_path),
        })
    }
}

/// Generic event parsing function
///
/// # Type Parameters
/// * `T` - Event type to be parsed, must implement ByteParseable
/// * `F` - Function type to convert T to TpmEventLog
///
/// # Parameters
/// * `parser` - Byte reader
/// * `wrapper` - Wrapper function to convert parsed event to TpmEventLog
/// * `event_name` - Event type name, used for error messages
/// 
/// # Returns
/// * `Result<TpmEventLog, PluginError>` - Parsed event or error
/// 
/// # Description
/// This function parses an event of type T using the provided parser and wrapper function.
/// 
/// # Errors
/// * `PluginError::InputError` - If input data is invalid or cannot be parsed
pub fn parse_typed_event<T, F>(
    parser: &mut ByteReader,
    wrapper: F,
    event_name: &str
) -> Result<TpmEventLog, PluginError>
where
    T: ByteParseable,
    F: FnOnce(T) -> TpmEventLog
{
    T::parse_from(parser)
        .map(wrapper)
        .map_err(|e| PluginError::InputError(
            format!("Failed to parse {}: {}", event_name, e)
        ))
}
