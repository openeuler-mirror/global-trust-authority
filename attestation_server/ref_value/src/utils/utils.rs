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

use log::{error, info};
use jwt::jwt_parser::JwtParser;
use key_management::api::{CryptoOperations, DefaultCryptoImpl, SignResponse};
use crate::entities::db_model::rv_db_model::ActiveModel;
use crate::entities::inner_model::rv_content::RefValueDetails;
use crate::entities::inner_model::rv_model::RefValueModel;
use crate::error::ref_value_error::RefValueError;
use crate::error::ref_value_error::RefValueError::{InvalidParameter, JsonParseError};

pub struct Utils {}

impl Utils {
    /// Parses reference value details from JWT content
    ///
    /// # Arguments
    /// * `content` - JWT formatted content string
    ///
    /// # Returns
    /// * `Ok(RefValueDetails)` - Successfully parsed reference value details
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * JWT parsing fails
    /// * JSON parsing fails
    pub fn parse_rv_detail_from_jwt_content(content: &str) -> Result<RefValueDetails, RefValueError> {
        let payload = JwtParser::get_payload(content).map_err(|e| InvalidParameter(e.to_string()))?;
        serde_json::from_str::<RefValueDetails>(&payload).map_err(|e| JsonParseError(e.to_string()))
    }

    /// Signs a reference value model
    ///
    /// # Arguments
    /// * `model` - Reference value model to be signed
    ///
    /// # Returns
    /// * `Ok((Vec<u8>, String))` - Signature and key version
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Signing operation fails
    pub async fn sign_by_ref_value_model(model: &RefValueModel) -> Result<(Vec<u8>, String), RefValueError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(model.id.as_bytes());
        bytes.extend_from_slice(model.uid.as_bytes());
        bytes.extend_from_slice(model.name.as_bytes());
        bytes.extend_from_slice(model.attester_type.as_bytes());
        bytes.extend_from_slice(model.content.as_bytes());
        bytes.extend_from_slice(&[model.is_default as u8]);
        match DefaultCryptoImpl.sign(&bytes, "FSK").await {
            Ok(SignResponse {signature, key_version}) => {
                info!("Signed the ref_value model successfully");
                Ok((signature, key_version))
            }
            Err(e) => {
                error!("Sign failed: {}", e);
                Err(RefValueError::SignatureError(e.to_string()))
            }
        }
    }

    /// Signs a database reference value model
    ///
    /// # Arguments
    /// * `model` - Database reference value model to be signed
    ///
    /// # Returns
    /// * `Ok((Vec<u8>, String))` - Signature and key version
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Model encoding fails
    /// * Signing operation fails
    pub async fn sign_by_ref_value_db_model(model: ActiveModel) -> Result<(Vec<u8>, String), RefValueError> {
        let bytes = Self::encode_rv_db_model_to_bytes(model)?;
        match DefaultCryptoImpl.sign(&bytes, "FSK").await {
            Ok(SignResponse {signature, key_version}) => {
                info!("Signed the ref_value db model successfully");
                Ok((signature, key_version))
            }
            Err(e) => {
                error!("Sign failed: {}", e);
                Err(RefValueError::SignatureError(e.to_string()))
            }
        }
    }
    
    /// Encodes a database reference value model into a byte sequence
    ///
    /// # Arguments
    /// * `model` - Database reference value model to be encoded
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Encoded byte sequence
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Model is missing required fields (id, uid, name, attester_type, content, is_default)
    pub fn encode_rv_db_model_to_bytes(model: ActiveModel) -> Result<Vec<u8>, RefValueError> {
        let mut bytes = Vec::new();
        if None == model.id.clone().into_value() {
            error!("Model does not have an id, sign failed");
            return Err(RefValueError::SignatureError("Model does not have an id, sign failed".to_string()));
        }
        bytes.extend_from_slice(model.id.unwrap().as_bytes());
        if None == model.uid.clone().into_value() {
            error!("Model does not have an uid, sign failed");
            return Err(RefValueError::SignatureError("Model does not have an uid, sign failed".to_string()));
        }
        bytes.extend_from_slice(model.uid.unwrap().as_bytes());
        if None == model.name.clone().into_value() {
            error!("Model does not have a name, sign failed");
            return Err(RefValueError::SignatureError("Model does not have a name, sign failed".to_string()));
        }
        bytes.extend_from_slice(model.name.unwrap().as_bytes());
        if None == model.attester_type.clone().into_value() {
            error!("Model does not have a attester_type, sign failed");
            return Err(RefValueError::SignatureError("Model does not have a attester_type, sign failed".to_string()));
        }
        bytes.extend_from_slice(model.attester_type.unwrap().as_bytes());
        if None == model.content.clone().into_value() {
            error!("Model does not have a content, sign failed");
            return Err(RefValueError::SignatureError("Model does not have a content, sign failed".to_string()));
        }
        bytes.extend_from_slice(model.content.unwrap().as_bytes());
        if None == model.is_default.clone().into_value() {
            error!("Model does not have an is_default value, sign failed");
            return Err(RefValueError::SignatureError("Model does not have an is_default value, sign failed".to_string()));
        }
        bytes.extend_from_slice(&[model.is_default.unwrap() as u8]);
        Ok(bytes)
    }
}