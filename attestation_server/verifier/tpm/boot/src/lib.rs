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

mod byte_reader;
mod event;
mod verifier;

pub use event::model::{
    EventType, TpmEventLog,
    NO_ACTION_EVENT_SIZE, UEFI_PARTITION_NAME_SIZE,
    SPEC_ID_EVENT_SIGNATURE_03, SPEC_ID_EVENT_SIGNATURE_00, STARTUP_LOCALITY_SIGNATURE,
    TpmDigestEntry, TcgDigestAlgorithm, EventLogEntry, TcgEfiSpecIdEventAlgorithmSize,
    EfiSpecIdEvent, StartupLocalityEvent, EvNoActionEvent,
    SCrtmVersionEvent,
    EfiSignatureList, EfiSignatureData, UefiVariableDataEvent, EfiVariableSecureBoot, EfiLoadOption, EfiVariableData,
    UefiPlatformFirmwareBlobEvent, UefiPlatformFirmwareBlobEvent2, UefiFirmwareBlobEvent,
    EvSeparatorEvent, EventBaseString, PCClientTaggedEvent,
    UefiPartitionHeader, UefiPartitionEntry, UefiGptDataEvent,
    UefiImageLoadEvent
};

pub use event::parser::{
    TcgDigestParse, TcgDigestParseV1, TcgDigestParseV2,
    parse_uefi_variable_data_event, parse_typed_event
};
pub use event::log::EventLog;
pub use verifier::TpmBootPlugin;
pub use byte_reader::{
    ByteReader, ByteParseable,
    UEFI_GUID_SIZE
};
