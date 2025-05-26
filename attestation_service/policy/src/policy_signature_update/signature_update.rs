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

use ctor::ctor;
use key_management::key_manager::lifecycle::key_observer::observer_init::register::register_observer;
use key_management::key_manager::lifecycle::key_observer::KeyLifecycleObserver;
use key_management::key_manager::error::KeyManagerError;
use key_management::api::impls::default_crypto_impl::DefaultCryptoImpl;
use key_management::key_manager::model::VerifyAndUpdateParam;
use key_management::api::crypto_operations::CryptoOperations;
use std::{future::Future, pin::Pin, sync::Arc};
use sea_orm::DatabaseTransaction;
use common_log::{error, info};
use crate::constants::SIGNATURE_KEY_TYPE;
use crate::repositories::policy_repository::PolicyRepository;

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Debug)]
pub struct PolicyManager;

unsafe impl Send for PolicyManager{}
unsafe impl Sync for PolicyManager{}

impl  KeyLifecycleObserver for PolicyManager {
    fn signature_update(
        &self,
        key_version: &str,
        tx: Arc<DatabaseTransaction>,
    ) -> BoxFuture<Result<(), Box<KeyManagerError>>> {
        let key_version = key_version.to_string();
        Box::pin(async move {
            info!("PolicyManager: Updating policy signature... {}", key_version);
            let policies = PolicyRepository::get_policies_by_key_version(&tx, &key_version).await
                .map_err(|e| KeyManagerError::new(e.to_string()))?;
            if policies.is_empty() {
                return Ok(());
            }
            let crypto_ops = DefaultCryptoImpl;
            // Process policies in groups of 100
            for chunk in policies.chunks(100) {
                for policy in chunk {
                    let param = VerifyAndUpdateParam {
                        key_type: String::from(SIGNATURE_KEY_TYPE),
                        key_version: policy.key_version.clone(),
                        data: policy.encode_to_bytes(),
                        signature: policy.signature.clone(),
                    };
                    match crypto_ops.verify_and_update(&param).await {
                        Ok(response) => {
                            if !response.need_update {
                                continue;
                            }
                            if response.verification_success {
                                if let (Some(new_version), Some(new_signature)) = (response.key_version, response.signature) {
                                    PolicyRepository::update_policy_signature(&*tx, policy.policy_id.to_string(), &new_version, &new_signature).await
                                        .map_err(|e| KeyManagerError::new(&e.to_string()))?;
                                }
                            } else {
                                error!("Signature verification fails, start setting valid_code field to 1");
                                PolicyRepository::update_policy_corrupted(&*tx, policy.policy_id.to_string(), 1).await
                                    .map_err(|e| KeyManagerError::new(&e.to_string()))?;
                            }
                        },
                        Err(e) => {
                            error!("Failed to verify and update policy {}: {}", policy.policy_id, e);
                            continue;
                        }
                    }
                }
            }
            Ok(())
        })
    }


}

#[ctor]
fn register_policy_manager() {
    register_observer(Arc::new(PolicyManager));
}
