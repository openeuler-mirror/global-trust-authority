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

// Common base plugin trait for TPM plugins
use crate::config::TpmPluginConfig;
use crate::entity::{Evidence, Quote, Pcrs, Log, PcrValue};
use plugin_manager::{AgentPlugin, PluginError, PluginBase};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::pkey::PKey;
use openssl::x509::X509;
use openssl::bn::BigNum;
use openssl::ec:: {EcKey, EcGroup};
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use tss_esapi::{
    Context,
    structures::{
        PcrSelection,
        PcrSelectionList,
        PcrSelectionListBuilder,
        PcrSlot,
        Data,
        SignatureScheme,
        HashScheme,
        Public,
        CapabilityData,
    },
    traits::Marshall,
    handles::{KeyHandle, TpmHandle, PersistentTpmHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::NvAuth,
        ecc::EccCurve,
    },
    constants::{
        CapabilityType,
        response_code::Tss2ResponseCode,
    },
    abstraction::nv,
};
use std::io::Error as IoError;

const MAX_QUOTE_NONCE_SIZE: usize = 32;

pub trait TpmPluginBase: PluginBase + AgentPlugin {
    fn config(&self) -> &TpmPluginConfig;

    // --- Utility functions for hash algorithm and PCR slots conversion ---
    fn hash_alg_from_str(algo: &str) -> Result<HashingAlgorithm, PluginError> {
        match algo {
            "sha1" => Ok(HashingAlgorithm::Sha1),
            "sha256" => Ok(HashingAlgorithm::Sha256),
            "sha384" => Ok(HashingAlgorithm::Sha384),
            "sha512" => Ok(HashingAlgorithm::Sha512),
            "sm3" => Ok(HashingAlgorithm::Sm3_256),
            _ => Err(PluginError::InternalError(
                format!("Unknown hash algorithm: {}", algo),
            )),
        }
    }

    fn pcr_slots_from_indices(indices: &[i32]) -> Vec<PcrSlot> {
        indices.iter().filter_map(|&index| match index {
            0 => Some(PcrSlot::Slot0),
            1 => Some(PcrSlot::Slot1),
            2 => Some(PcrSlot::Slot2),
            3 => Some(PcrSlot::Slot3),
            4 => Some(PcrSlot::Slot4),
            5 => Some(PcrSlot::Slot5),
            6 => Some(PcrSlot::Slot6),
            7 => Some(PcrSlot::Slot7),
            8 => Some(PcrSlot::Slot8),
            9 => Some(PcrSlot::Slot9),
            10 => Some(PcrSlot::Slot10),
            11 => Some(PcrSlot::Slot11),
            12 => Some(PcrSlot::Slot12),
            13 => Some(PcrSlot::Slot13),
            14 => Some(PcrSlot::Slot14),
            15 => Some(PcrSlot::Slot15),
            16 => Some(PcrSlot::Slot16),
            17 => Some(PcrSlot::Slot17),
            18 => Some(PcrSlot::Slot18),
            19 => Some(PcrSlot::Slot19),
            20 => Some(PcrSlot::Slot20),
            21 => Some(PcrSlot::Slot21),
            22 => Some(PcrSlot::Slot22),
            23 => Some(PcrSlot::Slot23),
            _ => None,
        }).collect()
    }

    fn context_new(&self) -> Result<Context, PluginError> {
        let ctx = Context::new(self.config().tcti_config.clone());
        match ctx {
            Ok(context) => Ok(context),
            Err(e) => {
                match e {
                    tss_esapi::Error::Tss2Error(Tss2ResponseCode::FormatZero(response_code)) => {
                        let err = IoError::last_os_error();
                        Err(PluginError::InternalError(
                            format!("TPM error details: response code {:x}, system error: {}", response_code.0, err)
                        ))
                    },
                    _ => Err(PluginError::InternalError(format!("Failed to create TPM context: {}", e)))
                }
            }
        }
    }

    fn create_ctx_without_session(&self) -> Result<Context, PluginError> {
        let ctx = self.context_new()?;
        Ok(ctx)
    }

    fn get_nv_cert_data(context: &mut Context, nv_index: u64) -> Result<Vec<u8>, PluginError> {
        let index: u32 = u32::try_from(nv_index)
            .map_err(|_| PluginError::InternalError("Invalid NV index value".to_string()))?;
        let nv_idx: NvIndexTpmHandle = NvIndexTpmHandle::new(index)
            .map_err(|e| PluginError::InternalError(format!("Failed to create NV index handle: {}", e)))?;

        let nv_auth_handle: NvAuth = context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_idx))
                .map(|v| NvAuth::NvIndex(v.into()))
        }).map_err(|e| PluginError::InternalError(format!("Failed to get NV handle from TPM: {}", e)))?;

        let cert_data:Vec<u8> = context.execute_with_nullauth_session(|ctx| {
            nv::read_full(ctx, nv_auth_handle, nv_idx)
        })
            .map_err(|e| PluginError::InternalError(format!("Failed to read certificate from NV index: {}", e)))?;
        Ok(cert_data)
    }

    // Read X509 certificate from TPM NV
    fn read_cert_from_nv(ctx: &mut Context, nv_index: u64) -> Result<X509, PluginError> {
        let cert_data = Self::get_nv_cert_data(ctx, nv_index)?;

        // Convert to X509 certificate format
        X509::from_der(&cert_data)
            .map_err(|e| PluginError::InternalError(format!("Invalid certificate format: {}", e)))
    }

    // Convert TPM public key to OpenSSL format for comparison
    fn convert_tpm_pubkey_to_openssl(ak_public: tss_esapi::structures::Public) -> Result<PKey<openssl::pkey::Public>, PluginError> {
        match ak_public {
            Public::Rsa { unique, .. } => {
                let n = unique.value();
                let rsa_p = BigNum::from_slice(n)
                    .map_err(|e| PluginError::InternalError(format!("Failed to get rsa p: {}", e)))?;
                let rsa_q = BigNum::from_u32(65537)
                    .map_err(|e| PluginError::InternalError(format!("Failed to get rsa q: {}", e)))?;
                let rsa = Rsa::from_public_components(
                    rsa_p,
                    rsa_q // Default exponent
                )
                    .map_err(|e| PluginError::InternalError(format!("Failed to create RSA key: {}", e)))?;
                PKey::from_rsa(rsa)
                    .map_err(|e| PluginError::InternalError(format!("Failed to get p key from rsa: {}", e)))
            },
            Public::Ecc { unique, parameters, .. } => {
                let x = unique.x();
                let y = unique.y();
                let group = match parameters.ecc_curve() {
                    EccCurve::NistP256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                        .map_err(|e| PluginError::InternalError(format!("Failed to create NIST P-256 group: {}", e)))?,
                    EccCurve::NistP384 => EcGroup::from_curve_name(Nid::SECP384R1)
                        .map_err(|e| PluginError::InternalError(format!("Failed to create NIST P-384 group: {}", e)))?,
                    EccCurve::NistP521 => EcGroup::from_curve_name(Nid::SECP521R1)
                        .map_err(|e| PluginError::InternalError(format!("Failed to create NIST P-521 group: {}", e)))?,
                    EccCurve::Sm2P256 => EcGroup::from_curve_name(Nid::SM2)
                        .map_err(|e| PluginError::InternalError(format!("Failed to create SM2 group: {}", e)))?,
                    _ => return Err(PluginError::InternalError("Unsupported ECC curve".to_string())),
                };
                let ecc_x = BigNum::from_slice(x)
                    .map_err(|e| PluginError::InternalError(format!("Failed to create ECC x coordinate: {}", e)))?;
                let ecc_y = BigNum::from_slice(y)
                    .map_err(|e| PluginError::InternalError(format!("Failed to create ECC y coordinate: {}", e)))?;
                let ec_key = EcKey::from_public_key_affine_coordinates(
                    &group,
                    &ecc_x,
                    &ecc_y
                )
                    .map_err(|e| PluginError::InternalError(format!("Failed to create ECC key: {}", e)))?;
                PKey::from_ec_key(ec_key)
                    .map_err(|e| PluginError::InternalError(format!("Failed to create PKey from ECC: {}", e)))
            },
            _ => Err(PluginError::InternalError("Unsupported key type".to_string())),
        }
    }

    // Validates that certificate's common name matches the node_id
    fn validate_cert_common_name(cert: &X509, node_id: &str) -> Result<(), PluginError> {
        // Extract the common name from the certificate
        let subject_name = cert.subject_name();
        let common_name_entry = subject_name.entries_by_nid(Nid::COMMONNAME).next();
        let common_name = match common_name_entry {
            Some(entry) => entry.data().as_utf8()
                .map_err(|e| PluginError::InternalError(format!("Failed to extract common name: {}", e)))?
                .to_string(),
            None => return Err(PluginError::InternalError("Common name not found in certificate".to_string())),
        };

        // Check if the node_id matches the common name
        if common_name != node_id {
            return Err(PluginError::InternalError("Node ID does not match the common name in the certificate".to_string()));
        }

        Ok(())
    }

    // Check if PCRs exist for the specified hash algorithm
    fn check_pcr_availability(context: &mut Context, pcr_hash_alg: HashingAlgorithm) -> Result<(), PluginError> {
        // Query TPM supported PCRs and algorithms
        let (capability_data, _more_data) = context.get_capability(
            CapabilityType::AssignedPcr,
            0,              // starting property
            20              // maximum count to return
        ).map_err(|e| PluginError::InternalError(format!("Failed to get TPM capabilities: {}", e)))?;

        // check PCRs for specified algorithm
        match capability_data {
            CapabilityData::AssignedPcr(pcrs_data) => {
                // Find PCR selection for the specified hash algorithm
                let pcr_selection: &PcrSelection = pcrs_data.get_selections()
                    .iter()
                    .find(|pcr_select| pcr_select.hashing_algorithm() == pcr_hash_alg)
                    .ok_or_else(|| PluginError::InternalError(
                        format!("Hash algorithm {:?} is not supported by TPM", pcr_hash_alg)
                    ))?;

                // Check if any PCRs are available for the algorithm
                if pcr_selection.selected().is_empty() {
                    return Err(PluginError::InternalError(
                        format!("No PCRs available for hash algorithm {:?}", pcr_hash_alg)
                    ));
                }
            },
            _ => return Err(PluginError::InternalError(
                "Received invalid capability data pcr hash algo from TPM".to_string()
            )),
        }
        Ok(())
    }

    // Common methods shared by all TPM plugins
    fn collect_aik(&self, node_id: &str) -> Result<String, PluginError> {
        let mut ctx = self.create_ctx_without_session()?;

        // Get the persistent AK handle and check if it exists
        let persistent_handle = PersistentTpmHandle::new(self.config().ak_handle as u32)
            .map_err(|e| PluginError::InternalError(format!("Invalid AK handle value: {}", e)))?;

        let tpm_handle = TpmHandle::Persistent(persistent_handle);
        let ak_handle = ctx.tr_from_tpm_public(tpm_handle)
            .map_err(|e| PluginError::InternalError(format!("AK key does not exist in TPM: {}", e)))?;

        // Read the AK public key from TPM
        let (ak_public, _, _) = ctx.execute_with_nullauth_session(|ctx| {
            ctx.read_public(ak_handle.into())
        }).map_err(|e| PluginError::InternalError(format!("Failed to read AK public key: {}", e)))?;

        // Read certificate from TPM NV index
        let ak_cert = Self::read_cert_from_nv(&mut ctx, self.config().ak_nv_index.try_into().unwrap())?;

        // Verify that certificate's public key matches the AK public key
        let cert_pubkey = ak_cert.public_key()
            .map_err(|e| PluginError::InternalError(format!("Failed to extract public key from certificate: {}", e)))?;

        // Convert TPM public key to OpenSSL format for comparison
        let tpm_pubkey_openssl = Self::convert_tpm_pubkey_to_openssl(ak_public)?;

        // Compare the public keys
        if !tpm_pubkey_openssl.public_eq(&cert_pubkey) {
            return Err(PluginError::InternalError(
                "AK public key does not match the key in certificate".to_string()
            ));
        }

        // Validates that certificate's common name matches the node_id
        Self::validate_cert_common_name(&ak_cert, node_id)?;

        // Return base64 encoded certificate
        let cert_der = ak_cert.to_der()
            .map_err(|e| PluginError::InternalError(format!("Failed to convert certificate to DER: {}", e)))?;

        let encoded_cert = STANDARD.encode(cert_der);
        let pem_cert = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", encoded_cert);

        Ok(pem_cert)
    }

    fn collect_pcrs_quote(&self, nonce: &[u8]) -> Result<(Quote, Pcrs), PluginError> {
        let mut context: Context = self.context_new()?;
        let pcr_hash_alg: HashingAlgorithm = Self::hash_alg_from_str(self.config().pcr_selection.hash_alg.as_str())?;

        // Check if PCRs exist for the specified hash algorithm
        Self::check_pcr_availability(&mut context, pcr_hash_alg)?;
        let pcr_banks: &Vec<i32> = &self.config().pcr_selection.banks;

        // Check if any PCR bank index is out of valid range (0-23)
        if let Some(invalid_pcr) = pcr_banks.iter().find(|&&pcr| !(0..=23).contains(&pcr)) {
            return Err(PluginError::InternalError(
                format!("Invalid PCR bank index {} in configuration. PCR indices must be between 0 and 23", invalid_pcr)
            ));
        }

        // Build the PCR selection list
        let pcr_slots: Vec<PcrSlot> = Self::pcr_slots_from_indices(pcr_banks);
        let pcr_selection_list: PcrSelectionList = PcrSelectionListBuilder::new()
            .with_selection(pcr_hash_alg, &pcr_slots)
            .build()
            .map_err(|e| PluginError::InternalError(format!("Failed to create PCR selection list: {}", e)))?;

        let quote: Quote = self.collect_quote(&mut context, pcr_selection_list.clone(), nonce)?;
        let pcrs: Pcrs = self.collect_pcrs(&mut context, pcr_selection_list, pcr_banks)?;

        Ok((quote, pcrs))
    }

    fn collect_pcrs(
        &self,
        context: &mut Context,
        pcr_selection_list: PcrSelectionList,
        pcr_banks: &[i32]
    ) -> Result<Pcrs, PluginError> {
        let (_, pcr_selection_out, pcr_digests) = context.pcr_read(pcr_selection_list)
            .map_err(|e| PluginError::InternalError(format!("Failed to read PCR values: {}", e)))?;

        // Get the first PCR selection (currently only one selection is supported)
        let pcr_selection: &PcrSelection = pcr_selection_out.get_selections().first()
            .ok_or_else(|| PluginError::InternalError("No PCR selection found".to_string()))?;

        // Validate PCR selection results
        let selected_count: usize = pcr_selection.selected().len();
        let expected_count: usize = pcr_banks.len();
        let digest_count: usize = pcr_digests.value().len();

        if selected_count != expected_count || selected_count != digest_count {
            return Err(PluginError::InternalError(format!(
                "PCR selection mismatch - expected: {}, selected: {}, digests: {}",
                expected_count, selected_count, digest_count
            )));
        }

        // Build PCR values list
        let pcr_values: Vec<PcrValue> = pcr_selection
            .selected()
            .iter()
            .zip(pcr_digests.value())
            .zip(pcr_banks.iter())
            .map(|((_selection, digest), &bank_index)| PcrValue {
                pcr_index: bank_index,
                pcr_value: hex::encode(digest.value()),
            })
            .collect();

        // Return the Pcrs struct
        Ok(Pcrs {
            hash_alg: self.config().pcr_selection.hash_alg.clone(),
            pcr_values,
        })
    }

    fn collect_quote(
        &self,
        context: &mut Context,
        pcr_selection_list: PcrSelectionList,
        nonce: &[u8]
    ) -> Result<Quote, PluginError> {
        // Trim the nonce to 32 bytes if it exceeds 32 bytes
        let nonce: &[u8] = &nonce[..std::cmp::min(nonce.len(), MAX_QUOTE_NONCE_SIZE)];

        // Get the persistent AK handle and convert it to KeyHandle
        let persistent_handle = PersistentTpmHandle::new(self.config().ak_handle as u32)
            .map_err(|e| PluginError::InternalError(format!("Invalid AK handle value: {}", e)))?;
        let tpm_handle = TpmHandle::Persistent(persistent_handle);
        let ak_handle: KeyHandle = context.tr_from_tpm_public(tpm_handle)
            .map_err(|e| PluginError::InternalError(format!("Failed to get AK handle from TPM: {}", e)))?
            .into();

        // Create qualifying data from nonce
        let qualifying_data = Data::try_from(nonce.to_vec())
            .map_err(|e| PluginError::InternalError(format!("Failed to create qualifying data: {}", e)))?;

        let signature_scheme = match &self.config().quote_signature_scheme {
            Some(quote_signature_scheme) => {
                let hash_alg = &quote_signature_scheme.hash_alg;
                let signature_alg = &quote_signature_scheme.signature_alg;
                
                let hash_scheme = match hash_alg.as_str() {
                    "sha1" => HashScheme::new(HashingAlgorithm::Sha1),
                    "sha256" => HashScheme::new(HashingAlgorithm::Sha256),
                    "sha384" => HashScheme::new(HashingAlgorithm::Sha384),
                    "sha512" => HashScheme::new(HashingAlgorithm::Sha512),
                    "sm3" => HashScheme::new(HashingAlgorithm::Sm3_256),
                    _ => return Err(PluginError::InternalError(format!("Unsupported hash algorithm: {}", hash_alg))),
                };
                
                match signature_alg.as_str() {
                    "rsassa" => SignatureScheme::RsaSsa {hash_scheme},
                    "rsapss" => SignatureScheme::RsaPss {hash_scheme},
                    "ecdsa" => SignatureScheme::EcDsa {hash_scheme},
                    "sm2" => SignatureScheme::Sm2 {hash_scheme},
                    _ => return Err(PluginError::InternalError(format!("Unsupported signature algorithm: {}", signature_alg))),
                }
            },
            None => {
                SignatureScheme::Null
            }
        };
        
        // Get quote and signature from TPM
        let (quote, signature) = context.execute_with_nullauth_session(|ctx| {
            ctx.quote(
                ak_handle,
                qualifying_data,
                signature_scheme,
                pcr_selection_list,
            )
        })
        .map_err(|e| PluginError::InternalError(format!("Failed to get quote from TPM: {}", e)))?;

        // Marshall quote and signature to bytes
        let quote_bytes = quote.marshall()
            .map_err(|e| PluginError::InternalError(format!("Failed to marshall quote: {}", e)))?;
        let signature_bytes = signature.marshall()
            .map_err(|e| PluginError::InternalError(format!("Failed to marshall signature: {}", e)))?;

        // Base64 encode the quote and signature
        let quote_data = STANDARD.encode(quote_bytes);
        let signature_data = STANDARD.encode(signature_bytes);

        // Return the Quote struct
        Ok(Quote {
            quote_data,
            signature: signature_data,
        })
    }
    
    // Plugin-specific log collection method that must be implemented by each plugin
    fn collect_log(&self) -> Result<Vec<Log>, PluginError>;
    
    // Default implementation for collect_evidence that can be used by all plugins
    fn collect_evidence_impl(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<serde_json::Value, PluginError> {
        let node_id = match node_id {
            Some(node_id) => node_id,
            None => return Err(PluginError::InputError("Node ID is required".to_string())),
        };

        let nonce = nonce.unwrap_or(&[]);

        // collect ak_cert, validate node_id
        let ak_cert = self.collect_aik(node_id)?;

        let (quote, pcrs) = self.collect_pcrs_quote(nonce)?;

        // Use the plugin's own collect_log implementation
        let logs = self.collect_log()?;

        // Create Evidence struct instance
        let evidence = Evidence {
            ak_cert,
            quote,
            pcrs,
            logs,
        };
        
        serde_json::to_value(evidence)
            .map_err(|e| PluginError::InternalError(format!("Failed to serialize evidence: {}", e)))
    }
}