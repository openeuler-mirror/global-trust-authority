//! Event Serialization Module
//!
//! This module implements serialization functionality for various event types in the TPM event log,
//! converting them to JSON format.
//! It includes serialization logic for various UEFI events, firmware BLOB events, signature lists,
//! and other data structures.
//! Used to format output evidence in JSON format for later use by the policy engine.
//!
//! By implementing the Serialize trait,
//! it provides a unified interface to serialize different event types into readable JSON format.
//!

use serde::{
    Serialize, Serializer,
    ser::SerializeStruct,
};
use hex;
use crate::event_type::{
    EventType, TpmEventLog,
    EfiSpecIdEvent, EvNoActionEvent,
    SCrtmVersionEvent,
    EfiLoadOption, EfiVariableData, EfiVariableSecureBoot, UefiVariableDataEvent,
    UefiPlatformFirmwareBlobEvent, UefiPlatformFirmwareBlobEvent2, UefiFirmwareBlobEvent,
    EvSeparatorEvent, EventBaseString, PCClientTaggedEvent,
    UefiPartitionHeader, UefiPartitionEntry, UefiGptDataEvent,
    UefiImageLoadEvent
};

/// When serializing EventType to JSON, it needs to be converted to the standard definition,
/// for example EvNoAction -> EV_NO_ACTION
impl Serialize for EventType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

/// Serializes string values to JSON objects
///
/// Removes null characters
///
/// # Parameters
/// * `serializer` - The serializer
/// * `struct_name` - Structure name
/// * `value` - The string value to be serialized
///
/// # Returns
/// * Serialized JSON object or error
fn serialize_string<S>(
    serializer: S,
    struct_name: &'static str,
    value: &str
) -> Result<S::Ok, S::Error>
where
    S: Serializer
{
    let mut state = serializer.serialize_struct(struct_name, 1)?; // field number
    state.serialize_field("value", &value.trim_end_matches('\0'))?;
    state.end()
}

/// Serializes firmware BLOB data to JSON objects
///
/// # Parameters
/// * `serializer` - The serializer
/// * `blob_base` - BLOB base address
/// * `blob_length` - BLOB length
///
/// # Returns
/// * Serialized JSON object or error
fn serialize_firmware_blob<S>(
    serializer: S,
    blob_base: u64,
    blob_length: u64
) -> Result<S::Ok, S::Error>
where
    S: Serializer 
{
    let mut state = serializer.serialize_struct("FirmwareBlob", 2)?; // field number
    state.serialize_field("blob_base", &format!("0x{:x}", blob_base))?;
    state.serialize_field("blob_length", &format!("0x{:x}", blob_length))?;
    state.end()
}

/// Serializes firmware BLOB data with description to JSON objects
///
/// # Parameters
/// * `serializer` - The serializer
/// * `description` - BLOB description
/// * `blob_base` - BLOB base address
/// * `blob_length` - BLOB length
///
/// # Returns
/// * Serialized JSON object or error
fn serialize_firmware_blob2<S>(
    serializer: S,
    description: &str,
    blob_base: u64, 
    blob_length: u64
) -> Result<S::Ok, S::Error>
where
    S: Serializer 
{
    let mut state = serializer.serialize_struct("FirmwareBlob", 3)?; // field number
    state.serialize_field("description", description)?;
    state.serialize_field("blob_base", &format!("0x{:x}", blob_base))?;
    state.serialize_field("blob_length", &format!("0x{:x}", blob_length))?;
    state.end()
}

/// Serializes UEFI platform firmware BLOB event
impl Serialize for UefiPlatformFirmwareBlobEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        serialize_firmware_blob(serializer, self.blob_base, self.blob_length)
    }
}

/// Serializes UEFI platform firmware BLOB event (version 2)
impl Serialize for UefiPlatformFirmwareBlobEvent2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        serialize_firmware_blob2(serializer, &self.blob_description, self.blob_base, self.blob_length)
    }
}

/// Serializes UEFI firmware BLOB event, calling different serialization methods based on type
impl Serialize for UefiFirmwareBlobEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            UefiFirmwareBlobEvent::UefiPlatformFirmwareString(s) => {
                serialize_string(serializer, "UefiPlatformFirmwareString", s)
            },
            UefiFirmwareBlobEvent::UefiPlatformFirmwareBlob(blob) => {
                serialize_firmware_blob(serializer, blob.blob_base, blob.blob_length)
            },
            UefiFirmwareBlobEvent::UefiPlatformFirmwareBlob2(blob) => {
                serialize_firmware_blob2(serializer, &blob.blob_description, blob.blob_base, blob.blob_length)
            }
        }
    }
}

/// Serializes No Action Event, including SpecIdEvent and StartupLocalityEvent
impl Serialize for EvNoActionEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            EvNoActionEvent::SpecIdEvent(spec_id) => {
                let mut state = serializer.serialize_struct("SpecIdEvent", 1)?; // field number
                state.serialize_field("spec_id", spec_id)?;
                state.end()
            },
            EvNoActionEvent::StartupLocality(locality) => {
                let mut state = serializer.serialize_struct("StartupLocality", 1)?; // field number
                state.serialize_field("startup_locality", locality)?;
                state.end()
            },
            EvNoActionEvent::Unknown(data) => {
                let mut state = serializer.serialize_struct("Unknown", 1)?; // field number
                state.serialize_field("value", &hex::encode(data))?;
                state.end()
            }
        }
    }
}

/// Serializes event base string
impl Serialize for EventBaseString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        serialize_string(serializer, "EventBaseString", &self.value)
    }
}

/// Serializes EFI specification ID event, including spec version info and supported digest algorithms
impl Serialize for EfiSpecIdEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EfiSpecIdEvent", 8)?; // field number
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("platform_class", &self.platform_class)?;
        state.serialize_field("family_minor", &self.family_minor)?;
        state.serialize_field("family_major", &self.family_major)?;
        state.serialize_field("spec_version", &self.spec_version)?;
        state.serialize_field("uintn_size", &self.uintn_size)?;
        state.serialize_field("algorithm_count", &self.algorithm_count)?;
        state.serialize_field("digest_algorithms", &self.digest_algorithms)?;
        state.serialize_field("vendor_info_size", &self.vendor_info_size)?;

        if self.vendor_info_size > 0 {
            state.serialize_field("vendor_info", &self.vendor_info)?;
        }
        
        state.end()
    }
}

/// Serializes separator event, serializing the separator value as a hexadecimal string
impl Serialize for EvSeparatorEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("EvSeparatorEvent", 1)?; // field number
        state.serialize_field("value", &format!("{:08x}", self.value))?;
        state.end()
    }
}

/// Serializes EFI load option, including various attributes of boot options
impl Serialize for EfiLoadOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("EfiLoadOption", 4)?; // field number
        state.serialize_field("enabled", &self.attributes)?;
        state.serialize_field("file_path_list_length", &self.file_path_list_length)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("device_path", &hex::encode(self.device_path.clone()))?;
        state.end()
    }
}

/// Serializes PC client tagged event, including event ID and event data
impl Serialize for PCClientTaggedEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("PCClientTaggedEvent", 3)?; // field number
        state.serialize_field("tagged_event_id", &format!("0x{:08x}", self.tagged_event_id))?;
        state.serialize_field("tagged_event_data_size", &self.tagged_event_data_size)?;
        state.serialize_field("tagged_event_data", &hex::encode(self.tagged_event_data.clone()))?;
        state.end()
    }
}

/// Serializes S-CRTM version event, serializing version information as a string
impl Serialize for SCrtmVersionEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        serialize_string(serializer, "SCrtmVersionEvent", &self.version)
    }
}

/// Serializes EFI Secure Boot variable, including enabled status
impl Serialize for EfiVariableSecureBoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("EfiVariableSecureBoot", 1)?;
        state.serialize_field("enabled", &self.enabled)?;
        state.end()
    }
}

/// Serializes EFI variable data, calling different serialization methods based on variable data type
impl Serialize for EfiVariableData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            EfiVariableData::SecureBoot(secure_boot) => {
                let mut state = serializer.serialize_struct("SecureBootData", 1)?;
                state.serialize_field("enabled", &secure_boot.enabled)?;
                state.end()
            },
            EfiVariableData::Boot(boot_option) => {
                let mut state = serializer.serialize_struct("Boot", 4)?;
                state.serialize_field("enabled", &boot_option.attributes)?;
                state.serialize_field("file_path_list_length", &boot_option.file_path_list_length)?;
                state.serialize_field("description", &boot_option.description)?;
                state.serialize_field("device_path", &hex::encode(&boot_option.device_path))?;
                state.end()
            },
            EfiVariableData::BootOrder(order) => {
                let mut state = serializer.serialize_struct("BootOrder", 1)?;
                state.serialize_field("boot_order", order)?;
                state.end()
            },
            EfiVariableData::SignatureList(list) => {
                let mut state = serializer.serialize_struct("SignatureList", 1)?;
                state.serialize_field("signature_list", list)?;
                state.end()
            },
            EfiVariableData::VariableAuthority(auth) => {
                let mut state = serializer.serialize_struct("VariableAuthority", 1)?;
                state.serialize_field("value", &auth.value)?;
                state.end()
            },
            EfiVariableData::AuthoritySignatureList(list) => {
                let mut state = serializer.serialize_struct("AuthoritySignatureList", 1)?;
                state.serialize_field("signature_type", &list.signature_type)?;
                state.serialize_field("signatures", &list.signatures)?;
                state.end()
            },
            EfiVariableData::Unknown(value) => {
                let mut state = serializer.serialize_struct("Unknown", 1)?;
                state.serialize_field("value", &hex::encode(value))?;
                state.end()
            }
        }
    }
}

/// Serializes UEFI variable data event, including variable name, unicode name, and variable data
impl Serialize for UefiVariableDataEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("UefiVariableDataEvent", 3)?;
        state.serialize_field("variable_name", &self.variable_name)?;
        state.serialize_field("unicode_name", &self.unicode_name)?;
        state.serialize_field("variable_data", &self.variable_data)?;
        state.end()
    }
}

/// Serializes UEFI image load event, including image location in memory, image length in memory,
/// image link time address, length of device path, and device path
impl Serialize for UefiImageLoadEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("UefiImageLoadEvent", 5)?;
        state.serialize_field("image_location_in_memory", &format!("0x{:x}", self.image_location_in_memory))?;
        state.serialize_field("image_length_in_memory", &self.image_length_in_memory)?;
        state.serialize_field("image_link_time_address", &format!("0x{:x}", self.image_link_time_address))?;
        state.serialize_field("length_of_device_path", &self.length_of_device_path)?;
        state.serialize_field("device_path", &self.device_path)?;
        state.end()
    }
}

/// Serializes UEFI GPT header, including signature, revision, header size, header CRC32, reserved,
/// my LBA, alternate LBA, first usable LBA, last usable LBA, disk GUID, partition entries LBA,
/// number of partition entries, size of partition entry, and partition entry array CRC32
impl Serialize for UefiPartitionHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("UefiPartitionHeader", 11)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("revision", &format!("0x{:x}", self.revision))?;
        state.serialize_field("header_size", &self.header_size)?;
        state.serialize_field("header_crc32", &format!("0x{:x}", self.header_crc32))?;
        state.serialize_field("my_lba", &format!("0x{:x}", self.my_lba))?;
        state.serialize_field("alternate_lba", &format!("0x{:x}", self.alternate_lba))?;
        state.serialize_field("first_usable_lba", &format!("0x{:x}", self.first_usable_lba))?;
        state.serialize_field("last_usable_lba", &format!("0x{:x}", self.last_usable_lba))?;
        state.serialize_field("disk_guid", &self.disk_guid)?;
        state.serialize_field("partition_entries_lba", &format!("0x{:x}", self.partition_entries_lba))?;
        state.serialize_field("number_of_partition_entries", &self.number_of_partition_entries)?;
        state.serialize_field("size_of_partition_entry", &self.size_of_partition_entry)?;
        state.serialize_field("partition_entry_array_crc32", &format!("0x{:x}", self.partition_entry_array_crc32))?;
        state.end()
    }
}

/// Serializes UEFI GPT partition entry, including partition type GUID, unique partition GUID,
/// starting LBA, ending LBA, attributes, and partition name
impl Serialize for UefiPartitionEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("UefiPartitionEntry", 5)?;
        state.serialize_field("partition_type_guid", &self.partition_type_guid)?;
        state.serialize_field("unique_partition_guid", &self.unique_partition_guid)?;
        state.serialize_field("starting_lba", &format!("0x{:x}", self.starting_lba))?;
        state.serialize_field("ending_lba", &format!("0x{:x}", self.ending_lba))?;
        state.serialize_field("attributes", &format!("0x{:x}", self.attributes))?;
        state.serialize_field("partition_name", &self.partition_name)?;
        state.end()
    }
}

/// Serializes UEFI GPT data event, including GPT header and partition entries
impl Serialize for UefiGptDataEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut state = serializer.serialize_struct("UefiGptDataEvent", 3)?;
        state.serialize_field("uefi_partition_header", &self.uefi_partition_header)?;
        state.serialize_field("number_of_partitions", &self.number_of_partitions)?;
        state.serialize_field("partitions", &self.partitions)?;
        state.end()
    }
}

/// Serializes TPM event log content, calling different serialization methods based on event type
impl Serialize for TpmEventLog {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TpmEventLog::EventBase(s) => {
                let mut state = serializer.serialize_struct("EventBase", 1)?; // field number
                state.serialize_field("value", &hex::encode(s))?;
                state.end()
            },
            // Delegates to each type's own serialization method
            TpmEventLog::EventNoAction(e) => e.serialize(serializer),
            TpmEventLog::EventBaseStr(e) => e.serialize(serializer),
            TpmEventLog::EventSeparator(e) => e.serialize(serializer),
            TpmEventLog::EventEfiFirmwareBlob(e) => e.serialize(serializer),
            TpmEventLog::EventPCClientTagged(e) => e.serialize(serializer),
            TpmEventLog::EventSCrtmVersion(e) => e.serialize(serializer),
            TpmEventLog::EventUefiPlatformFirmwareBlob(e) => e.serialize(serializer),
            TpmEventLog::EventUefiPlatformFirmwareBlob2(e) => e.serialize(serializer),
            TpmEventLog::EventUefiVariable(e) => e.serialize(serializer),
            TpmEventLog::EventEfiBootServicesApplication(e) => e.serialize(serializer),
            TpmEventLog::EventEfiGptEvent(e) => e.serialize(serializer),
        }
    }
}
