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

use crate::entities::{cert_info, cert_revoked_list};
use crate::repositories::cert_repository::CertRepository;
use crate::services::cert_service::ValidCode;
use ctor::ctor;
use key_management::api::crypto_operations::CryptoOperations;
use key_management::api::impls::default_crypto_impl::DefaultCryptoImpl;
use key_management::key_manager::error::KeyManagerError;
use key_management::key_manager::lifecycle::key_observer::observer_init::register::register_observer;
use key_management::key_manager::lifecycle::key_observer::KeyLifecycleObserver;
use key_management::key_manager::model::VerifyAndUpdateParam;
use sea_orm::{ActiveValue, DatabaseTransaction};
use std::{future::Future, pin::Pin, sync::Arc};
use common_log::{debug, error, info};

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Debug)]
pub struct CertManager;

unsafe impl Send for CertManager {}
unsafe impl Sync for CertManager {}

impl KeyLifecycleObserver for CertManager {
    fn signature_update(
        &self,
        key_version: &str,
        tx: Arc<DatabaseTransaction>,
    ) -> BoxFuture<Result<(), Box<KeyManagerError>>> {
        let key_version = key_version.to_string();
        Box::pin(async move {
            info!(
                "CertManager: Updating certificate signature... {}",
                key_version
            );
            let mut total_pages =
                CertRepository::batch_get_all_certs_total_pages(&tx, 100, &key_version)
                    .await
                    .map_err(|e| {
                        error!("Failed to query certificate page size: {:?}", e);
                        KeyManagerError::new(e.to_string())
                    })?;
            for page in 0..total_pages {
                let cert_models: Vec<cert_info::Model> =
                    CertRepository::batch_get_certs(&tx, page, 100, &key_version)
                        .await
                        .map_err(|e| {
                            error!("Failed to query certificate: {:?}", e);
                            KeyManagerError::new(e.to_string())
                        })?;
                for cert_info_model in cert_models {
                    let crypto_ops = DefaultCryptoImpl;
                    let mut cert_sig = cert_info_model.clone();
                    cert_sig.signature = None;
                    cert_sig.key_version = None;
                    cert_sig.key_id = None;
                    cert_sig.valid_code = None;
                    let data = serde_json::to_string(&cert_sig).unwrap_or("".to_string());
                    let param = VerifyAndUpdateParam {
                        key_type: "FSK".to_string(),
                        key_version: cert_info_model.key_version.unwrap().clone(),
                        data: data.into_bytes(),
                        signature: cert_info_model.signature.unwrap().clone(),
                    };
                    match crypto_ops.verify_and_update(&param).await {
                        Ok(response) => {
                            if !response.need_update {
                                continue;
                            }
                            if response.verification_success {
                                if let (Some(new_version), Some(new_signature)) =
                                    (response.key_version, response.signature)
                                {
                                    let cert_info_active_model=
                                        cert_info::ActiveModel {
                                            signature: ActiveValue::Set(Option::from(
                                                new_signature,
                                            )),
                                            key_version: ActiveValue::Set(Option::from(
                                                new_version,
                                            )),
                                            ..Default::default()
                                        };
                                    CertRepository::update_cert_info_when_signature_update(
                                        &tx,
                                        &cert_info_model.id,
                                        cert_info_model.version.clone().unwrap_or(0),
                                        cert_info_active_model,
                                    )
                                        .await
                                        .map_err(|e| {
                                            error!("Failed to update certificate signature and key_version: {:?}",e);
                                            KeyManagerError::new(e.to_string())
                                        })?;
                                }
                            } else {
                                error!("Signature verification fails, start setting valid_code field to 1");
                                if cert_info_model.valid_code.eq(&Some(ValidCode::NORMAL)) {
                                    match CertRepository::update_cert_valid_code(
                                        &tx,
                                        &cert_info_model.id,
                                        Some(1),
                                    )
                                        .await
                                    {
                                        Ok(_) => debug!("Successfully updated cert"),
                                        Err(e) => error!("Failed to update cert: {}", e),
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "Failed to verify and update cert {}: {}",
                                cert_info_model.owner.unwrap(),
                                e
                            );
                            continue;
                        }
                    }
                }
            }
            info!("Certificate key signature completed");
            total_pages =
                CertRepository::batch_get_all_revoke_certs_total_pages(&tx, 100, &key_version)
                    .await
                    .map_err(|e| {
                        error!("Failed to query revocation certificate: {:?}", e);
                        KeyManagerError::new(e.to_string())
                    })?;
            for page in 0..total_pages {
                let revoke_cert_models =
                    CertRepository::batch_get_revoke_certs(&tx, page, 100, &key_version)
                        .await
                        .map_err(|e| {
                            error!("Failed to query revocation certificate: {:?}", e);
                            KeyManagerError::new(e.to_string())
                        })?;
                for revoke_cert_info_model in revoke_cert_models {
                    let crypto_ops = DefaultCryptoImpl;
                    let mut cert_sig = revoke_cert_info_model.clone();
                    cert_sig.signature = None;
                    cert_sig.key_version = None;
                    cert_sig.key_id = None;
                    cert_sig.valid_code = None;
                    let data = serde_json::to_string(&cert_sig).unwrap_or("".to_string());
                    let param = VerifyAndUpdateParam {
                        key_type: "FSK".to_string(),
                        key_version: revoke_cert_info_model.key_version.unwrap().clone(),
                        data: data.into_bytes(),
                        signature: revoke_cert_info_model.signature.unwrap().clone(),
                    };
                    match crypto_ops.verify_and_update(&param).await {
                        Ok(response) => {
                            if !response.need_update {
                                continue;
                            }
                            if response.verification_success {
                                if let (Some(new_version), Some(new_signature)) =
                                    (response.key_version, response.signature)
                                {
                                    let revoke_active_model: cert_revoked_list::ActiveModel =
                                        cert_revoked_list::ActiveModel {
                                            signature: ActiveValue::Set(Option::from(
                                                new_signature,
                                            )),
                                            key_version: ActiveValue::Set(Option::from(
                                                new_version,
                                            )),
                                            ..Default::default()
                                        };
                                    CertRepository::update_revoke_cert_info(
                                        &tx,
                                        &revoke_cert_info_model.id,
                                        revoke_active_model,
                                    )
                                        .await
                                        .map_err(|e| {
                                            error!("Failed to update revocation certificate signature and key_version: {:?}", e);
                                            KeyManagerError::new(e.to_string())
                                        })?;
                                }
                            } else {
                                error!("Signature verification fails, start setting valid_code field to 1");
                                if revoke_cert_info_model
                                    .valid_code
                                    .eq(&Some(ValidCode::NORMAL))
                                {
                                    match CertRepository::update_cert_revoked_valid_code(
                                        &tx,
                                        &revoke_cert_info_model.id,
                                        Some(1),
                                    )
                                        .await
                                    {
                                        Ok(_) => debug!("Successfully updated cert"),
                                        Err(e) => error!("Failed to update cert: {}", e),
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "Failed to verify and update cert {}: {}",
                                revoke_cert_info_model.serial_num.unwrap(),
                                e
                            );
                            continue;
                        }
                    }
                }
            }
            info!("Revocation certificate key signature completed");
            Ok(())
        })
    }
}

#[ctor]
fn register_policy_manager() {
    register_observer(Arc::new(CertManager));
}
