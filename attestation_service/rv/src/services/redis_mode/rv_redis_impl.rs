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

use crate::entities::db_model::rv_dtl_redis_model::{RvRedisModel, RvRedisModelBuilder};
use crate::entities::inner_model::rv_model::RefValueModel;
use crate::entities::request_body::rv_del_req_body::RvDelReqBody;
use crate::entities::request_body::rv_update_req_body::RvUpdateReqBody;
use crate::error::ref_value_error::RefValueError;
use crate::error::ref_value_error::RefValueError::InvalidParameter;
use crate::repositories::rv_db_repo::RvDbRepo;
use crate::repositories::rv_dtl_db_repo::RvDtlDbRepo;
use crate::repositories::rv_rds_repo::RvRedisRepo;
use crate::services::rv_trait::RefValueTrait;
use crate::utils::utils::Utils;
use actix_web::web::Data;
use log::{error, info};
use sea_orm::{DatabaseConnection, TransactionTrait};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct RvRedisImpl;

impl RvRedisImpl {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl RefValueTrait for RvRedisImpl {
    async fn add(&self, conn: Data<Arc<DatabaseConnection>>, rv_model: &RefValueModel) -> Result<(), RefValueError> {
        let txn = conn.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        RvDbRepo::add(&txn, rv_model, 100).await?;
        let mut details = Utils::parse_rv_detail_from_jwt_content(&rv_model.content)?;
        details.set_all_ids(&rv_model.id);
        let rds_models = details
            .reference_values
            .into_iter()
            .map(|rv_dtl| {
                RvRedisModelBuilder::new()
                    .user_id(&rv_model.uid)
                    .attester_type(&rv_model.attester_type)
                    .rv_id(&rv_dtl.ref_value_id)
                    .file_name(&rv_dtl.file_name)
                    .sha256(&rv_dtl.sha256)
                    .build()
            })
            .collect();
        RvRedisRepo::batch_insert(rds_models).await?;
        txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    async fn update(
        &self,
        conn: Data<Arc<DatabaseConnection>>,
        user_id: &str,
        update_req_body: &RvUpdateReqBody,
    ) -> Result<(i32, String), RefValueError> {
        let txn = conn.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        let (version, org_name, org_attester_type) =
            RvDbRepo::update(&txn, &user_id, &update_req_body.id, &update_req_body).await.map_err(|e| {
                error!("Reference value update failed: {}", e);
                e
            })?;
        let (is_name_changed, new_name) =
            update_req_body.name.as_ref().map(|name| (true, name.to_string())).unwrap_or((false, String::new()));

        let (is_content_changed, new_content) = update_req_body
            .content
            .as_ref()
            .map(|content| (true, content.to_string()))
            .unwrap_or((false, String::new()));
        if is_content_changed {
            let mut details = Utils::parse_rv_detail_from_jwt_content(&new_content)?;
            details.set_all_ids(&update_req_body.id);
            let rds_models = details
                .reference_values
                .into_iter()
                .map(|rv_dtl| {
                    RvRedisModelBuilder::new()
                        .user_id(user_id)
                        .attester_type("tpm_ima")
                        .rv_id(&rv_dtl.ref_value_id)
                        .file_name(&rv_dtl.file_name)
                        .sha256(&rv_dtl.sha256)
                        .build()
                })
                .collect();
            RvRedisRepo::batch_delete_by_rv_id(vec![update_req_body.id.clone()]).await?;
            RvRedisRepo::batch_insert(rds_models).await?;
        }
        Ok((version, if is_name_changed { new_name } else { org_name }))
    }

    async fn delete(
        &self,
        conn: Data<Arc<DatabaseConnection>>,
        user_id: &str,
        del_type: &str,
        del_req_body: &RvDelReqBody,
    ) -> Result<(), RefValueError> {
        let del_req_body_clone = del_req_body.clone();
        match del_type {
            "all" => {
                RvDbRepo::del_all(&conn, &user_id).await?;
                RvRedisRepo::delete_by_user_id(&user_id).await
            },
            "id" => {
                let txn = conn.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                RvDbRepo::del_by_id(&txn, &user_id, &del_req_body_clone.ids.clone().unwrap()).await?;
                RvRedisRepo::batch_delete_by_rv_id(del_req_body_clone.ids.unwrap()).await?;
                txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                Ok(())
            },
            "type" => {
                let txn = conn.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                RvDbRepo::del_by_type(&conn, &user_id, &del_req_body_clone.attester_type.clone().unwrap()).await?;
                RvRedisRepo::delete_by_user_and_type(&user_id, &del_req_body_clone.attester_type.unwrap()).await?;
                txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                Ok(())
            },
            _ => Err(InvalidParameter(format!("Invalid delete_type: {}", del_req_body.delete_type))),
        }
    }

    fn verify<'a>(
        &'a self,
        measurements: &'a Vec<String>,
        user_id: &'a str,
        attester_type: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            let measurements_ref: Vec<String> = measurements.iter().map(|s| s.to_string()).collect();
            let mut matched: HashSet<String> = HashSet::new();

            let items =
                match RvRedisRepo::query_by_user_and_type(measurements_ref.clone(), &user_id, &attester_type).await {
                    Ok(items) => items,
                    Err(e) => {
                        error!("query dtl in redis failed. {}", e.to_string());
                        return Ok(measurements_ref);
                    },
                };

            for item in items {
                matched.insert(item);
            }

            let unmatched: Vec<String> =
                measurements.into_iter().filter(|m| !matched.contains(*m)).map(String::from).collect();
            info!("unmatched: {:?}", unmatched);
            Ok(unmatched)
        })
    }
}
