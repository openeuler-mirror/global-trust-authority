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

//! Event Type Definitions
//!
//! This module defines various event types, structures, and enumerations used in TPM event logs.
//! Includes event type enumerations, digest algorithms, event log entries, and other core data structures.
//! These types define the basic structure and organization of TPM event logs.

use serde::Serialize;
use std::fmt;
use tpm_common_verifier::AlgorithmId;

pub const NO_ACTION_EVENT_SIZE: usize = 16;
pub const UEFI_PARTITION_NAME_SIZE: usize = 36;

/// Spec id event signature 03
pub const SPEC_ID_EVENT_SIGNATURE_03: &[u8] = &[
    0x53, 0x70, 0x65, 0x63, 0x20,  // "Spec "
    0x49, 0x44, 0x20,              // "ID "
    0x45, 0x76, 0x65, 0x6E, 0x74,  // "Event"
    0x30, 0x33,                    // "03"
    0x00                           // Null terminator
];

/// Spec id event signature 00
pub const SPEC_ID_EVENT_SIGNATURE_00: &[u8] = &[
    0x53, 0x70, 0x65, 0x63, 0x20,  // "Spec "
    0x49, 0x44, 0x20,              // "ID "
    0x45, 0x76, 0x65, 0x6E, 0x74,  // "Event"
    0x30, 0x30,                    // "00"
    0x00                           // Null terminator
];

/// Byte representation of startup locality identifier
pub const STARTUP_LOCALITY_SIGNATURE: &[u8] = &[
    0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70,           // "Startup"
    0x4C, 0x6F, 0x63, 0x61, 0x6C, 0x69, 0x74, 0x79,     // "Locality"
    0x00                                                // Null terminator
];

/// TCG Event Type Enumeration
///
/// Defines various event types in TPM event logs
/// Includes standard TPM event types and UEFI-specific event types
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EventType {
    EvPrebootCert = 0x00000000,
    EvPostCode = 0x00000001,
    EvUnused = 0x00000002,
    EvNoAction = 0x00000003,
    EvSeparator = 0x00000004,
    EvAction = 0x00000005,
    EvEventTag = 0x00000006,
    EvSCrtmContents = 0x00000007,
    EvSCrtmVersion = 0x00000008,
    EvCpuMicrocode = 0x00000009,
    EvPlatformConfigFlags = 0x0000000A,
    EvTableOfDevices = 0x0000000B,
    EvCompactHash = 0x0000000C,
    EvIpl = 0x0000000D,
    EvIplPartitionData = 0x0000000E,
    EvNonhostCode = 0x0000000F,
    EvNonhostConfig = 0x00000010,
    EvNonhostInfo = 0x00000011,
    EvOmitBootDeviceEvents = 0x00000012,
    EvPostCode2 = 0x00000013,

    // EFI specific event types
    EvEfiEventBase = 0x80000000,
    EvEfiVariableDriverConfig = 0x80000001,
    EvEfiVariableBoot = 0x80000002,
    EvEfiBootServicesApplication = 0x80000003,
    EvEfiBootServicesDriver = 0x80000004,
    EvEfiRuntimeServicesDriver = 0x80000005,
    EvEfiGptEvent = 0x80000006,
    EvEfiAction = 0x80000007,
    EvEfiPlatformFirmwareBlob = 0x80000008,
    EvEfiHandoffTables = 0x80000009,
    EvEfiPlatformFirmwareBlob2 = 0x8000000A,
    EvEfiHandoffTables2 = 0x8000000B,
    EvEfiVariableBoot2 = 0x8000000C,
    EvEfiGptEvent2 = 0x8000000D,
    EvEfiHcrtmEvent = 0x80000010,

    EvEfiVariableAuthority = 0x800000E0,
    EvEfiSpdmFirmwareBlob = 0x800000E1,
    EvEfiSpdmFirmwareConfig = 0x800000E2,
    EvEfiSpdmDevicePolicy = 0x800000E3,
    EvEfiSpdmDeviceAuthority = 0x800000E4,
    Unknown = 0xFFFFFFFF,
}

impl EventType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x00000000 => Some(Self::EvPrebootCert),
            0x00000001 => Some(Self::EvPostCode),
            0x00000002 => Some(Self::EvUnused),
            0x00000003 => Some(Self::EvNoAction),
            0x00000004 => Some(Self::EvSeparator),
            0x00000005 => Some(Self::EvAction),
            0x00000006 => Some(Self::EvEventTag),
            0x00000007 => Some(Self::EvSCrtmContents),
            0x00000008 => Some(Self::EvSCrtmVersion),
            0x00000009 => Some(Self::EvCpuMicrocode),
            0x0000000A => Some(Self::EvPlatformConfigFlags),
            0x0000000B => Some(Self::EvTableOfDevices),
            0x0000000C => Some(Self::EvCompactHash),
            0x0000000D => Some(Self::EvIpl),
            0x0000000E => Some(Self::EvIplPartitionData),
            0x0000000F => Some(Self::EvNonhostCode),
            0x00000010 => Some(Self::EvNonhostConfig),
            0x00000011 => Some(Self::EvNonhostInfo),
            0x00000012 => Some(Self::EvOmitBootDeviceEvents),
            0x00000013 => Some(Self::EvPostCode2),

            // EFI specific event types
            0x80000000 => Some(Self::EvEfiEventBase),
            0x80000001 => Some(Self::EvEfiVariableDriverConfig),
            0x80000002 => Some(Self::EvEfiVariableBoot),
            0x80000003 => Some(Self::EvEfiBootServicesApplication),
            0x80000004 => Some(Self::EvEfiBootServicesDriver),
            0x80000005 => Some(Self::EvEfiRuntimeServicesDriver),
            0x80000006 => Some(Self::EvEfiGptEvent),
            0x80000007 => Some(Self::EvEfiAction),
            0x80000008 => Some(Self::EvEfiPlatformFirmwareBlob),
            0x80000009 => Some(Self::EvEfiHandoffTables),
            0x8000000A => Some(Self::EvEfiPlatformFirmwareBlob2),
            0x8000000B => Some(Self::EvEfiHandoffTables2),
            0x8000000C => Some(Self::EvEfiVariableBoot2),
            0x8000000D => Some(Self::EvEfiGptEvent2),
            0x80000010 => Some(Self::EvEfiHcrtmEvent),

            0x800000E0 => Some(Self::EvEfiVariableAuthority),
            0x800000E1 => Some(Self::EvEfiSpdmFirmwareBlob),
            0x800000E2 => Some(Self::EvEfiSpdmFirmwareConfig),
            0x800000E3 => Some(Self::EvEfiSpdmDevicePolicy),
            0x800000E4 => Some(Self::EvEfiSpdmDeviceAuthority),
            _ => None,
        }
    }

    pub fn requires_digest_verification(&self) -> bool {
        match self {
            Self::EvEfiVariableDriverConfig |
            Self::EvEfiVariableAuthority |
            Self::EvSCrtmVersion |
            Self::EvSeparator |
            Self::EvPlatformConfigFlags |
            Self::EvTableOfDevices |
            Self::EvOmitBootDeviceEvents |
            Self::EvEfiGptEvent |
            Self::EvEfiGptEvent2 |
            Self::EvEfiSpdmDevicePolicy |
            Self::EvEfiSpdmDeviceAuthority => true,
            _ => false,
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvPrebootCert => write!(f, "EV_PRVBOOT_CERT"),
            Self::EvPostCode => write!(f, "EV_POST_CODE"),
            Self::EvUnused => write!(f, "EV_UNUSED"),
            Self::EvNoAction => write!(f, "EV_NO_ACTION"),
            Self::EvSeparator => write!(f, "EV_SEPARATOR"),
            Self::EvAction => write!(f, "EV_ACTION"),
            Self::EvEventTag => write!(f, "EV_EVENT_TAG"),
            Self::EvSCrtmContents => write!(f, "EV_S_CRTM_CONTENTS"),
            Self::EvSCrtmVersion => write!(f, "EV_S_CRTM_VERSION"),
            Self::EvCpuMicrocode => write!(f, "EV_CPU_MICROCODE"),
            Self::EvPlatformConfigFlags => write!(f, "EV_PLATFORM_CONFIG_FLAGS"),
            Self::EvTableOfDevices => write!(f, "EV_TABLE_OF_DEVICES"),
            Self::EvCompactHash => write!(f, "EV_COMPACT_HASH"),
            Self::EvIpl => write!(f, "EV_IPL"),
            Self::EvIplPartitionData => write!(f, "EV_IPL_PARTITION_DATA"),
            Self::EvNonhostCode => write!(f, "EV_NONHOST_CODE"),
            Self::EvNonhostConfig => write!(f, "EV_NONHOST_CONFIG"),
            Self::EvNonhostInfo => write!(f, "EV_NONHOST_INFO"),
            Self::EvOmitBootDeviceEvents => write!(f, "EV_OMIT_BOOT_DEVICE_EVENTS"),
            Self::EvPostCode2 => write!(f, "EV_POST_CODE2"),
            Self::EvEfiEventBase => write!(f, "EV_EFI_EVENT_BASE"),
            Self::EvEfiVariableDriverConfig => write!(f, "EV_EFI_VARIABLE_DRIVER_CONFIG"),
            Self::EvEfiVariableBoot => write!(f, "EV_EFI_VARIABLE_BOOT"),
            Self::EvEfiBootServicesApplication => write!(f, "EV_EFI_BOOT_SERVICES_APPLICATION"),
            Self::EvEfiBootServicesDriver => write!(f, "EV_EFI_BOOT_SERVICES_DRIVER"),
            Self::EvEfiRuntimeServicesDriver => write!(f, "EV_EFI_RUNTIME_SERVICES_DRIVER"),
            Self::EvEfiGptEvent => write!(f, "EV_EFI_GPT_EVENT"),
            Self::EvEfiAction => write!(f, "EV_EFI_ACTION"),
            Self::EvEfiPlatformFirmwareBlob => write!(f, "EV_EFI_PLATFORM_FIRMWARE_BLOB"),
            Self::EvEfiHandoffTables => write!(f, "EV_EFI_HANDOFF_TABLES"),
            Self::EvEfiPlatformFirmwareBlob2 => write!(f, "EV_EFI_PLATFORM_FIRMWARE_BLOB2"),
            Self::EvEfiHandoffTables2 => write!(f, "EV_EFI_HANDOFF_TABLES2"),
            Self::EvEfiVariableBoot2 => write!(f, "EV_EFI_VARIABLE_BOOT2"),
            Self::EvEfiGptEvent2 => write!(f, "EV_EFI_GPT_EVENT2"),
            Self::EvEfiHcrtmEvent => write!(f, "EV_EFI_HCRTM_EVENT"),
            Self::EvEfiVariableAuthority => write!(f, "EV_EFI_VARIABLE_AUTHORITY"),
            Self::EvEfiSpdmFirmwareBlob => write!(f, "EV_EFI_SPDM_FIRMWARE_BLOB"),
            Self::EvEfiSpdmFirmwareConfig => write!(f, "EV_EFI_SPDM_FIRMWARE_CONFIG"),
            Self::EvEfiSpdmDevicePolicy => write!(f, "EV_EFI_SPDM_DEVICE_POLICY"),
            Self::EvEfiSpdmDeviceAuthority => write!(f, "EV_EFI_SPDM_DEVICE_AUTHORITY"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// TPM Digest Entry
///
/// Contains digest algorithm ID and digest value
pub struct TpmDigestEntry {
    pub algorithm_id: AlgorithmId,
    pub digest_value: String,
}

impl TpmDigestEntry {
    pub fn new(algorithm_id: AlgorithmId, digest_value: String) -> Self {
        Self {
            algorithm_id: algorithm_id,
            digest_value: digest_value,
        }
    }
}

/// TCG Digest Algorithm
///
/// Supports two versions of digest formats:
/// - V1: TCG 1.2 version, contains only SHA1 digest
/// - V2: TCG 2.0 version, supports multiple digest algorithms
pub enum TcgDigestAlgorithm {
    V1(String),
    V2(Vec<TpmDigestEntry>),
}

impl TcgDigestAlgorithm {
    pub fn get_digest_value(&self, hash_alg: AlgorithmId) -> String {
        match self {
            TcgDigestAlgorithm::V1(value) => value.clone(),
            TcgDigestAlgorithm::V2(digests) => {
                digests.iter()
                    .find(|d| d.algorithm_id == hash_alg)
                    .map(|d| d.digest_value.clone())
                    .unwrap_or_else(|| String::new())
            }
        }
    }
}

/// Event Log Entry
///
/// Represents a single entry in the TPM event log, including PCR index, event type, digest, and event data
pub struct EventLogEntry {
    pub event_number: u32,              // Event number
    pub pcr_index: u32,                 // PCR register index
    pub event_type: EventType,          // Event type
    pub digest: TcgDigestAlgorithm,     // Event digest
    pub event: TpmEventLog,             // Event data
}

/// TCG EFI Specification ID Event Algorithm Size
///
/// Describes supported digest algorithms and their sizes
#[derive(Serialize)]
pub struct TcgEfiSpecIdEventAlgorithmSize {
    pub algorithm_id: String,
    pub digest_size: u16,
}

impl TcgEfiSpecIdEventAlgorithmSize {
    pub fn new(algorithm_id: u16, digest_size: u16) -> Self {
        Self {
            algorithm_id: AlgorithmId::from(algorithm_id).to_string(),
            digest_size: digest_size
        }
    }
}

/// Specification ID Event Data
///
/// Contains TCG specification version information and supported digest algorithms
pub struct EfiSpecIdEvent {
    pub signature: String,                  // "Spec ID Event03"
    pub platform_class: u32,                // Platform class
    pub family_minor: u8,                   // Family minor
    pub family_major: u8,                   // Family major
    pub spec_version: u8,                   // Specification version
    pub uintn_size: u8,                     // UINTN data size (typically 2 or 4 bytes)
    pub algorithm_count: usize,             // Number of algorithms
    pub digest_algorithms: Vec<TcgEfiSpecIdEventAlgorithmSize>,   // List of supported digest algorithms
    pub vendor_info_size: u8,               // Vendor info size
    pub vendor_info: Vec<u8>,               // Vendor specific information
}

/// Startup Locality Event
///
/// Records TPM startup locality information
#[derive(Serialize)]
pub struct StartupLocalityEvent {
    pub signature: String,
    pub locality: u8,
}

/// No Action Event Data
/// Includes:
/// - SpecIdEvent and StartupLocalityEvent
/// - Platform Firmware VendorID and ReferenceManifestGUID
/// - TCG_HCRTMComponentEvent
/// - NV_Extend Events
///
/// New detailed parsing support for SpecIdEvent and StartupLocality
pub enum EvNoActionEvent {
    SpecIdEvent(EfiSpecIdEvent),
    StartupLocality(StartupLocalityEvent),
    Unknown(Vec<u8>),
}

#[derive(Serialize)]
pub struct EfiSignatureList {
    pub signature_type: String, // guid
    pub signature_list_size: u32,
    pub signature_header_size: u32,
    pub signature_size: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signature_header: Vec<u8>,
    pub signatures: Vec<EfiSignatureData>,
}

#[derive(Serialize)]
pub struct EfiSignatureData {
    pub signature_owner: String, // guid
    pub signature_data: String,
}

pub struct EfiVariableSecureBoot {
    pub enabled: String,  // "Yes" or "No"
}

pub struct EfiLoadOption{
    pub attributes: String,  // "Yes" or "No"
    pub file_path_list_length: u16,
    pub description: String,
    pub device_path: Vec<u8>,
}

/// UEFI Variable Data
///
/// Contains different types of UEFI variable data
pub enum EfiVariableData {
    SignatureList(Vec<EfiSignatureList>),       // Signature list
    SecureBoot(EfiVariableSecureBoot),          // Secure boot status
    VariableAuthority(EventBaseString),         // Variable authority
    AuthoritySignatureList(EfiSignatureData),   // Authority signature list
    BootOrder(Vec<String>),                     // Boot order
    Boot(EfiLoadOption),                        // Boot option
    Unknown(String),                            // Unknown data
}

/// UEFI Variable Event Data
pub struct UefiVariableDataEvent {
    pub variable_name: String,                  // Variable GUID
    pub unicode_name: String,                   // Variable name
    pub variable_data: EfiVariableData,         // Variable data (hex)
}

/// Platform Firmware Blob Event Data
pub struct UefiPlatformFirmwareBlobEvent {
    pub blob_base: u64,                         // Efi physical address
    pub blob_length: u64,                       // Length
}

/// Platform Firmware Blob Event2 Data
pub struct UefiPlatformFirmwareBlobEvent2 {
    pub blob_description: String,
    pub blob_base: u64,                         // Efi physical address
    pub blob_length: u64,                       // Length
}

/// Platform Firmware Blob Event3 Data
pub enum UefiFirmwareBlobEvent {
    UefiPlatformFirmwareString(String),
    UefiPlatformFirmwareBlob(UefiPlatformFirmwareBlobEvent),
    UefiPlatformFirmwareBlob2(UefiPlatformFirmwareBlobEvent2),
}

pub struct PCClientTaggedEvent {
    pub tagged_event_id: u32,
    pub tagged_event_data_size: u32,
    pub tagged_event_data: Vec<u8>,
}

/// S-CRTM Version Event Data
/// Version of the S-CRTM as either a 16-byte GUID or a UCS-2 string.
pub struct SCrtmVersionEvent {
    pub version: String,
}

/// Separator Event Data
pub struct EvSeparatorEvent {
    pub value: u32,                         // Separator value
}

pub struct EventBaseString {
    pub value: String,
}

/// Gpt header
pub struct UefiPartitionHeader {
    pub signature: String,                  // GPT header signature. 8-char ASCII string
    pub revision: u32,                      // Header version
    pub header_size: u32,                   // Header size
    pub header_crc32: u32,                  // Header CRC32
    pub reserved: u32,                      // Reserved
    pub my_lba: u64,                        // My LBA
    pub alternate_lba: u64,                 // Backup LBA
    pub first_usable_lba: u64,              // First usable LBA
    pub last_usable_lba: u64,               // Last usable LBA
    pub disk_guid: String,                  // Disk GUID
    pub partition_entries_lba: u64,         // Partition entries LBA
    pub number_of_partition_entries: u32,   // Number of partition entries
    pub size_of_partition_entry: u32,       // Size of partition entry
    pub partition_entry_array_crc32: u32,   // Partition entry array CRC32
}

/// GPT Partition Entry
pub struct UefiPartitionEntry {
    pub partition_type_guid: String,     // Partition type GUID
    pub unique_partition_guid: String,   // Unique partition GUID
    pub starting_lba: u64,               // Starting LBA
    pub ending_lba: u64,                 // Ending LBA
    pub attributes: u64,                 // Attributes
    pub partition_name: String,          // Partition name
}

/// EFI GPT Event Data
pub struct UefiGptDataEvent {
    pub uefi_partition_header: UefiPartitionHeader,     // GPT header signature
    pub number_of_partitions: u64,                      // Number of partition entries
    pub partitions: Vec<UefiPartitionEntry>,            // List of partition entries
}

pub struct UefiImageLoadEvent {
    pub image_location_in_memory: u64,          // Image location in memory
    pub image_length_in_memory: u64,            // Image length in memory
    pub image_link_time_address: u64,           // Link time address
    pub length_of_device_path: u64,             // Load options length
    pub device_path: String,                    // Device path (hex)
}

/// TPM Event Log Parsing Types
///
/// Represents different types of event data content
pub enum TpmEventLog {
    EventBase(Vec<u8>),                                     // Base event data (binary)
    EventBaseStr(EventBaseString),                          // Base event string
    EventEfiFirmwareBlob(UefiFirmwareBlobEvent),            // UEFI firmware BLOB event
    EventNoAction(EvNoActionEvent),                         // No action event
    EventSeparator(EvSeparatorEvent),                       // Separator event
    EventPCClientTagged(PCClientTaggedEvent),               // PC client tagged event
    EventSCrtmVersion(SCrtmVersionEvent),                   // S-CRTM version event
    EventUefiPlatformFirmwareBlob(UefiPlatformFirmwareBlobEvent), // UEFI platform firmware BLOB event
    EventUefiPlatformFirmwareBlob2(UefiPlatformFirmwareBlobEvent2), // UEFI platform firmware BLOB event (version 2)
    EventUefiVariable(UefiVariableDataEvent),               // UEFI variable event
    EventEfiBootServicesApplication(UefiImageLoadEvent),    // UEFI boot services application event
    EventEfiGptEvent(UefiGptDataEvent),                     // UEFI GPT event
}
