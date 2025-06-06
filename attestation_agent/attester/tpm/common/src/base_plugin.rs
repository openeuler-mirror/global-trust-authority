// Common base plugin trait for TPM plugins
use crate::config::TpmPluginConfig;
use crate::entity::{Evidence, Quote, Pcrs, Log, PcrValue};
use plugin_manager::{AgentPlugin, PluginError, PluginBase};
use serde_json;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::pkey::PKey;
use openssl::x509::X509;
use openssl::bn::BigNum;
use openssl::ec:: {EcKey, EcGroup};
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use hex;
use tss_esapi::{
    Context,
    structures::{
        PcrSelectionListBuilder,
        PcrSlot,
        Data,
        SignatureScheme,
        HashScheme,
        SymmetricDefinition,
        Public,
        CapabilityData,
    },
    interface_types::algorithm::HashingAlgorithm,
    traits::Marshall,
    handles::{KeyHandle, TpmHandle, PersistentTpmHandle, NvIndexHandle, NvIndexTpmHandle},
    interface_types::resource_handles,
    interface_types::ecc::EccCurve,
    constants::CapabilityType,
    constants::SessionType,
    attributes::SessionAttributesBuilder,
};

pub trait TpmPluginBase: PluginBase + AgentPlugin {
    fn config(&self) -> &TpmPluginConfig;
    
    // --- Utility functions for hash algorithm and PCR slots conversion ---
    fn hash_algo_from_str(algo: &str) -> Result<HashingAlgorithm, PluginError> {
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

    fn create_ctx_with_session(&self) -> Result<Context, PluginError> {
        let mut ctx = Context::new(self.config().tcti_config.clone())
            .map_err(|e| PluginError::InternalError(format!("Failed to create TPM context: {}", e)))?;
        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        ctx.tr_sess_set_attributes(
            session.unwrap(),
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();
        ctx.set_sessions((session, None, None));
    
        Ok(ctx)
    }

    // Read X509 certificate from TPM NV
    fn read_cert_from_nv(ctx: &mut Context, nv_index: u64) -> Result<X509, PluginError> {
        // Create NV index handle
        let nv_index_handle = NvIndexTpmHandle::new(nv_index as u32)
            .map_err(|e| PluginError::InternalError(format!("Invalid NV index value: {}", e)))?;
        
        // Get handle from TPM
        let nv_handle = ctx
            .tr_from_tpm_public(nv_index_handle.into())
            .map(NvIndexHandle::from)
            .map_err(|e| PluginError::InternalError(format!("Failed to get NV handle from TPM: {}", e)))?;

        // Get NV index public data to determine size
        let (nv_public, _) = ctx.nv_read_public(nv_handle)
            .map_err(|e| PluginError::InternalError(format!("Failed to read NV public data: {}", e)))?;
        
        let size = nv_public.data_size();
        
        // Read certificate data from NV
        let cert_data = ctx.nv_read(
            resource_handles::NvAuth::NvIndex(nv_handle),
            nv_handle,
            size as u16,
            0,  // Starting offset
        )
        .map_err(|e| PluginError::InternalError(format!("Failed to read certificate from NV index: {}", e)))?;

        // Convert to X509 certificate format
        X509::from_der(cert_data.value())
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
    fn check_pcr_availability(context: &mut Context, pcr_hash_algo: HashingAlgorithm) -> Result<(), PluginError> {
        // Query TPM supported PCRs and algorithms
        let (capability_data, _more_data) = context.get_capability(
            CapabilityType::AssignedPcr,
            0,              // starting property
            20              // maximum count to return
        ).map_err(|e| PluginError::InternalError(format!("Failed to get TPM capabilities: {}", e)))?;
        
        // check PCRs for specified algorithm
        match capability_data {
            CapabilityData::AssignedPcr(pcrs_data) => {
                let mut found_matching_algo = false;
                
                for pcr_select in pcrs_data.get_selections() {
                    if pcr_select.hashing_algorithm() == pcr_hash_algo {
                        found_matching_algo = true;
                        if pcr_select.selected().is_empty() {
                            return Err(PluginError::InternalError(
                                format!("No PCRs available for hash algorithm {:?}", pcr_hash_algo)
                            ));
                        }
                    }
                }
                if !found_matching_algo {
                    return Err(PluginError::InternalError(
                        format!("Hash algorithm {:?} is not supported by TPM", pcr_hash_algo)
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
        let mut ctx = self.create_ctx_with_session()?;
        
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
    
    fn collect_pcrs(&self) -> Result<Pcrs, PluginError> {
        // Implementation of collect_pcrs (same for all plugins)
        // Create a new TPM context
        let mut context = Context::new(self.config().tcti_config.clone())
            .map_err(|e| PluginError::InternalError(format!("Failed to create TPM context: {}", e)))?;

        let pcr_hash_algo = Self::hash_algo_from_str(self.config().pcr_selection.hash_algo.as_str())?;

        // Check if PCRs exist for the specified hash algorithm
        Self::check_pcr_availability(&mut context, pcr_hash_algo)?;

        // Build PCR selection list based on configured PCR selections
        let mut pcr_selection_builder = PcrSelectionListBuilder::new();

        let pcr_banks = self.config().pcr_selection.banks.clone();
        // Check if any PCR bank index is out of valid range (0-23)
        if let Some(invalid_pcr) = pcr_banks.iter().find(|&&pcr| pcr < 0 || pcr > 23) {
            return Err(PluginError::InternalError(
                format!("Invalid PCR bank index {} in configuration. PCR indices must be between 0 and 23", invalid_pcr)
            ));
        }
        let pcr_slots: Vec<PcrSlot> = Self::pcr_slots_from_indices(&pcr_banks);
        // Add the PCR selection to the builder
        pcr_selection_builder = pcr_selection_builder.with_selection(pcr_hash_algo, &pcr_slots);

        // Build the PCR selection list
        let pcr_selection_list = pcr_selection_builder.build()
            .map_err(|e| PluginError::InternalError(format!("Failed to create PCR selection list: {}", e)))?;

        let (_, _, pcr_digests) = context.pcr_read(pcr_selection_list)
            .map_err(|e| PluginError::InternalError(format!("Failed to read PCR values: {}", e)))?;

        // Get the selected PCR indices
        let pcr_indices = self.config().pcr_selection.banks.clone();

        // Convert PCR values to hex format and associate with correct PCR indices
        let mut pcr_values: Vec<PcrValue> = Vec::new();
        
        // Iterate through the PCR digests
        let values = pcr_digests.value();
        for (i, digest) in values.iter().enumerate() {
            // Use the corresponding PCR index if available, otherwise use the position
            let pcr_index = if i < pcr_indices.len() {
                pcr_indices[i]
            } else {
                (i as i32).try_into().unwrap()
            };
            
            pcr_values.push(PcrValue {
                pcr_index: pcr_index as i32,
                pcr_value: hex::encode(digest.value()),
            });
        }
        // Return the Pcrs struct
        Ok(Pcrs {
            hash_algo: self.config().pcr_selection.hash_algo.clone(),
            pcr_values,
        })
    }
    
    fn collect_quote(&self, nonce: &[u8]) -> Result<Quote, PluginError> {
        // Trim the nonce to 64 bytes if it exceeds 64 bytes
        let nonce = &nonce[..std::cmp::min(nonce.len(), 64)];

        // Create a new TPM context
        let mut context = Context::new(self.config().tcti_config.clone())
            .map_err(|e| PluginError::InternalError(format!("Failed to create TPM context: {}", e)))?;

        // Get the persistent AK handle and convert it to KeyHandle
        let persistent_handle = PersistentTpmHandle::new(self.config().ak_handle as u32)
            .map_err(|e| PluginError::InternalError(format!("Invalid AK handle value: {}", e)))?;
        let tpm_handle = TpmHandle::Persistent(persistent_handle);
        let ak_handle: KeyHandle = context.tr_from_tpm_public(tpm_handle)
            .map_err(|e| PluginError::InternalError(format!("Failed to get AK handle from TPM: {}", e)))?
            .into();

        // Build PCR selection list based on configured PCR selections
        let mut pcr_selection_builder = PcrSelectionListBuilder::new();
        
        // Convert the hash algorithm string to HashingAlgorithm
        let pcr_hash_algo = Self::hash_algo_from_str(self.config().pcr_selection.hash_algo.as_str())?;

        let pcr_banks = self.config().pcr_selection.banks.clone();
        // Check if any PCR bank index is out of valid range (0-23)
        if let Some(invalid_pcr) = pcr_banks.iter().find(|&&pcr| pcr < 0 || pcr > 23) {
            return Err(PluginError::InternalError(
                format!("Invalid PCR bank index {} in configuration. PCR indices must be between 0 and 23", invalid_pcr)
            ));
        }
        // Convert the PCR selections to PcrSlot values
        let pcr_slots: Vec<PcrSlot> = Self::pcr_slots_from_indices(&pcr_banks);
        
        // Add the PCR selection to the builder
        pcr_selection_builder = pcr_selection_builder.with_selection(pcr_hash_algo, &pcr_slots);
        
        // Build the PCR selection list
        let pcr_selection_list = pcr_selection_builder.build()
            .map_err(|e| PluginError::InternalError(format!("Failed to create PCR selection list: {}", e)))?;

        // Create qualifying data from nonce
        let qualifying_data = Data::try_from(nonce.to_vec())
            .map_err(|e| PluginError::InternalError(format!("Failed to create qualifying data: {}", e)))?;

        let signature_scheme = match &self.config().quote_signature_scheme {
            Some(quote_signature_scheme) => {
                let hash_algo = &quote_signature_scheme.hash_algo;
                let signature_algo = &quote_signature_scheme.signature_algo;
                
                let hash_scheme = match hash_algo.as_str() {
                    "sha1" => HashScheme::new(HashingAlgorithm::Sha1),
                    "sha256" => HashScheme::new(HashingAlgorithm::Sha256),
                    "sha384" => HashScheme::new(HashingAlgorithm::Sha384),
                    "sha512" => HashScheme::new(HashingAlgorithm::Sha512),
                    "sm3" => HashScheme::new(HashingAlgorithm::Sm3_256),
                    _ => return Err(PluginError::InternalError(format!("Unsupported hash algorithm: {}", hash_algo))),
                };
                
                match signature_algo.as_str() {
                    "rsassa" => SignatureScheme::RsaSsa {hash_scheme},
                    "rsapss" => SignatureScheme::RsaPss {hash_scheme},
                    "ecdsa" => SignatureScheme::EcDsa {hash_scheme},
                    "sm2" => SignatureScheme::Sm2 {hash_scheme},
                    _ => return Err(PluginError::InternalError(format!("Unsupported signature algorithm: {}", signature_algo))),
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

        let nonce = match nonce {
            Some(nonce) => nonce,
            None => &[],
        };

        // collect ak_cert, validate node_id
        let ak_cert = self.collect_aik(node_id)?;

        // collect quote
        let quote = self.collect_quote(&nonce)?;
        
        // collect pcrs
        let pcrs = self.collect_pcrs()?;
        
        // Use the plugin's own collect_log implementation
        let log = self.collect_log()?;

        // Create Evidence struct instance
        let evidence = Evidence {
            ak_cert,
            quote,
            pcrs,
            log,
        };
        
        serde_json::to_value(evidence)
            .map_err(|e| PluginError::InternalError(format!("Failed to serialize evidence: {}", e)))
    }
}