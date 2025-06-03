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

use crate::entities::db_model::rv_db_model::{ActiveModelBuilder, Model};
use crate::repositories::rv_db_repo::RvDbRepo;
use crate::utils::utils::Utils;
use ctor::ctor;
use common_log::{debug, error, info};
use key_management::api::crypto_operations::CryptoOperations;
use key_management::api::impls::default_crypto_impl::DefaultCryptoImpl;
use key_management::key_manager::error::KeyManagerError;
use key_management::key_manager::lifecycle::key_observer::observer_init::register::register_observer;
use key_management::key_manager::lifecycle::key_observer::KeyLifecycleObserver;
use key_management::key_manager::model::VerifyAndUpdateParam;
use sea_orm::{DatabaseTransaction};
use std::{future::Future, pin::Pin, sync::Arc};
use key_management::api::VerifyAndUpdateResponse;

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Debug)]
pub struct RvSigUpdate;

impl KeyLifecycleObserver for RvSigUpdate {
    fn signature_update(
        &self,
        key_version: &str,
        tx: Arc<DatabaseTransaction>,
    ) -> BoxFuture<Result<(), Box<KeyManagerError>>> {
        let key_version = key_version.to_string();
        Box::pin(async move {
            info!("Updating ref_value signature for key version: {}", key_version);

            let total_pages = Self::query_total_pages(&tx, &key_version).await?;

            for page in 0..total_pages {
                let models = Self::query_page_models(&tx, page, &key_version).await?;

                for model in models {
                    if let Err(e) = Self::process_model(&tx, model).await {
                        error!("Failed to process model: {}", e);
                    }
                }
            }

            info!("rv key signature rotation completed");
            Ok(())
        })
    }
}

impl RvSigUpdate {
    pub async fn query_total_pages(
        tx: &DatabaseTransaction,
        key_version: &str,
    ) -> Result<u64, KeyManagerError> {
        RvDbRepo::count_pages_by_key_version(tx, key_version, 100)
            .await
            .map_err(|e| {
                error!("Failed to query ref_value page size: {}", e);
                KeyManagerError::new(e.to_string())
            })
    }

    async fn query_page_models(
        tx: &DatabaseTransaction,
        page: u64,
        key_version: &str,
    ) -> Result<Vec<Model>, KeyManagerError> {
        RvDbRepo::query_page_by_key_version(tx, page, 100, key_version)
            .await
            .map_err(|e| {
                error!("Failed to query ref_value by page {}: {}", page, e);
                KeyManagerError::new(e.to_string())
            })
    }

    async fn process_model(
        tx: &DatabaseTransaction,
        model: Model,
    ) -> Result<(), KeyManagerError> {
        // 1. Encode model data
        let data_bytes = Utils::encode_rv_db_model_to_bytes(model.clone().into())
            .map_err(|e| {
                error!("Failed to encode model {}: {}", model.id, e);
                KeyManagerError::new(e.to_string())
            })?;

        // 2. Verify and update signature
        let param = VerifyAndUpdateParam {
            key_type: "FSK".to_string(),
            key_version: model.key_version.clone(),
            data: data_bytes,
            signature: model.signature.clone(),
        };

        match DefaultCryptoImpl.verify_and_update(&param).await {
            Ok(response) if response.need_update && response.verification_success => {
                Self::update_signature(tx, &model, response).await
            }
            Ok(response) if !response.verification_success => {
                Self::mark_as_invalid(tx, &model).await
            }
            Err(e) => {
                error!("Verification failed for model {}: {}", model.id, e);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn update_signature(
        tx: &DatabaseTransaction,
        model: &Model,
        response: VerifyAndUpdateResponse,
    ) -> Result<(), KeyManagerError> {
        let update_model = ActiveModelBuilder::new()
            .op_signature(response.signature)
            .op_key_version(response.key_version)
            .version(model.version + 1)
            .build();

        RvDbRepo::update_by_id_and_version(tx, update_model, &model.id, model.version)
            .await
            .map_err(|e| {
                error!("Failed to update signature for model {}: {}", model.id, e);
                KeyManagerError::new(e.to_string())
            })
    }

    async fn mark_as_invalid(
        tx: &DatabaseTransaction,
        model: &Model,
    ) -> Result<(), KeyManagerError> {
        error!("Signature verification failed for model {}, marking as invalid", model.id);

        let update_model = ActiveModelBuilder::new()
            .valid_code(1)
            .version(model.version + 1)
            .build();

        RvDbRepo::update_by_id_and_version(tx, update_model, &model.id, model.version)
            .await
            .map_err(|e| {
                error!("Failed to mark model {} as invalid: {}", model.id, e);
                KeyManagerError::new(e.to_string())
            })
    }
}

#[ctor]
fn register_rv_sig_update() {
    register_observer(Arc::new(RvSigUpdate));
}
