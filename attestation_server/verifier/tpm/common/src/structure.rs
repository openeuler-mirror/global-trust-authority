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

//! TPM structure, including TPM2.0 magic value, TPM2.0 attestation type, TPM clock information, algorithm id,
//! PCR selection, PCR information, signature algorithm type, RSA signature, ECC signature, and signature structure.
//! # Examples
//! See the `deserialize` method for an example of how to use the TpmsAttest struct.
use serde::{Serialize, Deserialize};
use std::convert::TryFrom;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};
use plugin_manager::PluginError;

/// TPM 2.0 Magic constant (byte representation of ASCII "TPM\x02")
pub const TPM2_GENERATED_VALUE: u32 = 0xff544347;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TpmStType {
    AttestNone = 0x0000,
    AttestQuote = 0x8018,
}

impl TryFrom<u16> for TpmStType {
    type Error = PluginError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(TpmStType::AttestNone),
            0x8018 => Ok(TpmStType::AttestQuote),
            _ => Err(PluginError::InputError(format!("Invalid TPMI_ST_ATTEST value: 0x{:04X}", value))),
        }
    }
}

/// TPM clock information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmsClockInfo {
    pub clock: u64,        // TPM clock count
    pub reset_count: u32,  // Reset count
    pub restart_count: u32, // Restart count
    pub safe: bool,        // Whether the clock is safe
}

impl TpmsClockInfo {
    pub fn deserialize(buffer: &mut Cursor<&[u8]>) -> Result<Self, PluginError> {
        let clock = buffer.read_u64::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize clock: {}", e)))?;
        let reset_count = buffer.read_u32::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize reset_count: {}", e)))?;
        let restart_count = buffer.read_u32::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize restart_count: {}", e)))?;
        let safe_byte = buffer.read_u8()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize safe: {}", e)))?;
        let safe = safe_byte != 0;

        Ok(TpmsClockInfo {
            clock,
            reset_count,
            restart_count,
            safe,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum AlgorithmId {
    Sha1 = 0x0004,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Sm3 = 0x0012,
    Unknown = 0xFFFF,
}

impl From<u16> for AlgorithmId {
    fn from(value: u16) -> Self {
        match value {
            0x0004 => AlgorithmId::Sha1,
            0x000B => AlgorithmId::Sha256,
            0x000C => AlgorithmId::Sha384,
            0x000D => AlgorithmId::Sha512,
            0x0012 => AlgorithmId::Sm3,
            _ => AlgorithmId::Unknown,
        }
    }

}

impl AlgorithmId {
    pub fn from_str(s: &str) -> Result<Self, PluginError> {
        match s {
            "sha1" => Ok(AlgorithmId::Sha1),
            "sha256" => Ok(AlgorithmId::Sha256),
            "sha384" => Ok(AlgorithmId::Sha384),
            "sha512" => Ok(AlgorithmId::Sha512),
            "sm3" => Ok(AlgorithmId::Sm3),
            _ => Err(PluginError::InputError(format!("Unsupported algorithm: {}", s))),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            AlgorithmId::Sha1 => "sha1".to_string(),
            AlgorithmId::Sha256 => "sha256".to_string(),
            AlgorithmId::Sha384 => "sha384".to_string(),
            AlgorithmId::Sha512 => "sha512".to_string(),
            AlgorithmId::Sm3 => "sm3".to_string(),
            AlgorithmId::Unknown => format!("UNKNOWN_0x{:04X}", *self as u16),
        }
    }

    pub fn digest_size(&self) -> u16 {
        match self {
            AlgorithmId::Sha1 => 20,
            AlgorithmId::Sha256 => 32,
            AlgorithmId::Sha384 => 48,
            AlgorithmId::Sha512 => 64,
            AlgorithmId::Sm3 => 32,
            AlgorithmId::Unknown => 0,
}
    }
}

/// PCR selection structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmsPcrSelection {
    pub hash_alg: AlgorithmId,     // Hash algorithm identifier
    pub size_of_select: u8,         // Size of select array
    pub pcr_select: Vec<u8>,        // PCR selection mask
}

impl TpmsPcrSelection {
    pub fn deserialize(buffer: &mut Cursor<&[u8]>) -> Result<Self, PluginError> {
        let alg = buffer.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize hash_alg: {}", e)))?;
        let hash_alg = AlgorithmId::from(alg);

        let size_of_select = buffer.read_u8()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize size_of_select: {}", e)))?;

        let mut pcr_select = vec![0u8; size_of_select as usize];
        buffer.read_exact(&mut pcr_select)
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize pcr_select: {}", e)))?;

        Ok(TpmsPcrSelection {
            hash_alg,
            size_of_select,
            pcr_select,
        })
    }

    /// Check if the specified PCR index is selected
    pub fn is_pcr_selected(&self, pcr_index: u32) -> bool {
        if pcr_index >= 8 * (self.size_of_select as u32) {
            return false;
        }

        let byte_index = (pcr_index / 8) as usize;
        let bit_index = pcr_index % 8;
        let mask = 1 << bit_index;

        byte_index < self.pcr_select.len() && (self.pcr_select[byte_index] & mask) != 0
    }
}

/// PCR information structure in Quote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmsQuoteInfo {
    pub pcr_select: Vec<TpmsPcrSelection>,  // PCR selection array
    pub pcr_digest: Vec<u8>,                // Digest of PCR values
}

impl TpmsQuoteInfo {
    pub fn deserialize(buffer: &mut Cursor<&[u8]>) -> Result<Self, PluginError> {
        let pcr_select_count = buffer.read_u32::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize pcr_select count: {}", e)))?;

        let mut pcr_select = Vec::new();
        for _ in 0..pcr_select_count {
            let selection = TpmsPcrSelection::deserialize(buffer)?;
            pcr_select.push(selection);
        }

        let digest_size = buffer.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize pcr_digest size: {}", e)))?;

        let mut pcr_digest = vec![0u8; digest_size as usize];
        buffer.read_exact(&mut pcr_digest)
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize pcr_digest: {}", e)))?;

        Ok(TpmsQuoteInfo {
            pcr_select,
            pcr_digest,
        })
    }

}

/// TPM Quote attestation structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmsAttest {
    pub magic: u32,                    // TPM magic value (must be TPM2_GENERATED_VALUE)
    pub type_: TpmStType,              // Attestation type
    pub qualified_signer: Vec<u8>,     // Qualified signer (usually AK name)
    pub extra_data: Vec<u8>,           // External data (usually nonce)
    pub clock_info: TpmsClockInfo,     // Clock information
    pub firmware_version: u64,         // Firmware version
    pub attested: TpmsQuoteInfo,       // Quote specific information
}

impl TpmsAttest {
    pub fn deserialize(data: &[u8]) -> Result<Self, PluginError> {
        let mut cursor = Cursor::new(data);

        // Read magic value
        let magic = cursor.read_u32::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize magic: {}", e)))?;

        if magic != TPM2_GENERATED_VALUE {
            return Err(PluginError::InputError(
                format!("Invalid magic value: 0x{:08X}, expected 0x{:08X}", magic, TPM2_GENERATED_VALUE)
            ));
        }

        // Read type
        let type_u16 = cursor.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize type: {}", e)))?;

        let type_ = TpmStType::try_from(type_u16)?;

        if type_ != TpmStType::AttestQuote {
            return Err(PluginError::InputError(
                format!("Expected Quote type, but got {:?}", type_)
            ));
        }

        // Read qualified signer (TPM2B_NAME)
        let name_size = cursor.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize qualified_signer size: {}", e)))?;

        let mut qualified_signer = vec![0u8; name_size as usize];
        cursor.read_exact(&mut qualified_signer)
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize qualified_signer: {}", e)))?;

        // Read extra data (TPM2B_DATA)
        let data_size = cursor.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize extra_data size: {}", e)))?;

        let mut extra_data = vec![0u8; data_size as usize];
        cursor.read_exact(&mut extra_data)
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize extra_data: {}", e)))?;

        // Read clock information
        let clock_info = TpmsClockInfo::deserialize(&mut cursor)?;

        // Read firmware version
        let firmware_version = cursor.read_u64::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize firmware_version: {}", e)))?;

        // Read proof information (Quote)
        let attested = TpmsQuoteInfo::deserialize(&mut cursor)?;

        Ok(TpmsAttest {
            magic,
            type_,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
            attested,
        })
    }
}

/// Signature algorithm type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tpm2SignatureAlgID {
    Rsa = 0x0001,
    RsaSsa = 0x0014,
    RsaPss = 0x0016,
    Ecdsa = 0x0018,
    Ecdaa = 0x001A,
    Sm2 = 0x001B,
    Unknown = 0xFFFF,
}

impl From<u16> for Tpm2SignatureAlgID {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => Tpm2SignatureAlgID::Rsa,
            0x0014 => Tpm2SignatureAlgID::RsaSsa,
            0x0016 => Tpm2SignatureAlgID::RsaPss,
            0x0018 => Tpm2SignatureAlgID::Ecdsa,
            0x001A => Tpm2SignatureAlgID::Ecdaa,
            0x001B => Tpm2SignatureAlgID::Sm2,
            _ => Tpm2SignatureAlgID::Unknown,
        }
    }
}

/// RSA signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmtSignatureRsa {
    pub hash: AlgorithmId,     // Hash algorithm
    pub signature: Vec<u8>,    // Signature value
}

impl TpmtSignatureRsa {
    pub fn deserialize(buffer: &mut Cursor<&[u8]>) -> Result<Self, PluginError> {
        // Read hash algorithm
        let hash_alg_u16 = buffer.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize hash algorithm: {}", e)))?;
        let hash = AlgorithmId::from(hash_alg_u16);

        // Read signature size and data
        let sig_size = buffer.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize signature size: {}", e)))?;

        let mut signature = vec![0u8; sig_size as usize];
        buffer.read_exact(&mut signature)
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize signature: {}", e)))?;

        Ok(TpmtSignatureRsa {
            hash,
            signature,
        })
    }
}

/// ECC signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmtSignatureEcc {
    pub hash: AlgorithmId,    // Hash algorithm
    pub signature_r: Vec<u8>,  // r coordinate
    pub signature_s: Vec<u8>,  // s coordinate
}

impl TpmtSignatureEcc {
    pub fn deserialize(buffer: &mut Cursor<&[u8]>) -> Result<Self, PluginError> {
        // Read hash algorithm
        let hash_alg_u16 = buffer.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize hash algorithm: {}", e)))?;
        let hash = AlgorithmId::from(hash_alg_u16);

        // Read R coordinate size and data
        let r_size = buffer.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize R coordinate size: {}", e)))?;

        let mut signature_r = vec![0u8; r_size as usize];
        buffer.read_exact(&mut signature_r)
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize R coordinate: {}", e)))?;

        // Read S coordinate size and data
        let s_size = buffer.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize S coordinate size: {}", e)))?;

        let mut signature_s = vec![0u8; s_size as usize];
        buffer.read_exact(&mut signature_s)
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize S coordinate: {}", e)))?;

        Ok(TpmtSignatureEcc {
            hash,
            signature_r,
            signature_s,
        })
    }
}

/// Signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmtSignature {
    pub sig_alg: Tpm2SignatureAlgID,
    pub signature: SignatureData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureData {
    RsaSignature(TpmtSignatureRsa),
    EccSignature(TpmtSignatureEcc),
}

impl TpmtSignature {
    pub fn deserialize(data: &[u8]) -> Result<Self, PluginError> {
        let mut cursor = Cursor::new(data);

        // Read signature algorithm
        let sig_alg_u16 = cursor.read_u16::<BigEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to deserialize signature algorithm: {}", e)))?;
        let sig_alg = Tpm2SignatureAlgID::from(sig_alg_u16);

        // Deserialize signature data based on algorithm type
        let signature = match sig_alg {
            Tpm2SignatureAlgID::Rsa| Tpm2SignatureAlgID::RsaSsa | Tpm2SignatureAlgID::RsaPss => {
                SignatureData::RsaSignature(TpmtSignatureRsa::deserialize(&mut cursor)?)
            },
            Tpm2SignatureAlgID::Ecdsa | Tpm2SignatureAlgID::Ecdaa | Tpm2SignatureAlgID::Sm2 => {
                SignatureData::EccSignature(TpmtSignatureEcc::deserialize(&mut cursor)?)
            },
            _ => return Err(PluginError::InputError(
                format!("Unsupported signature algorithm: {:?}", sig_alg)
            )),
        };

        Ok(TpmtSignature {
            sig_alg,
            signature,
        })
    }
}
