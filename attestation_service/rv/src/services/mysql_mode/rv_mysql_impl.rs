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

use crate::entities::db_model::rv_db_model::{ActiveModel, ActiveModelBuilder, Model as RvDbModel};
use crate::entities::db_model::rv_detail_db_model::Model as RvDtlDbModel;
use crate::entities::inner_model::rv_content::{RefValueDetail, RefValueDetails};
use crate::entities::inner_model::rv_model::{RefValueModel};
use crate::entities::request_body::rv_del_req_body::RvDelReqBody;
use crate::entities::request_body::rv_update_req_body::RvUpdateReqBody;
use crate::error::ref_value_error::RefValueError;
use crate::error::ref_value_error::RefValueError::{DbError, InvalidParameter};
use crate::repositories::rv_db_repo::RvDbRepo;
use crate::repositories::rv_dtl_db_repo::RvDtlDbRepo;
use crate::services::rv_trait::RefValueTrait;
use crate::utils::utils::Utils;
use actix_web::web::{Data};
use futures::{stream, StreamExt};
use jwt::jwt_parser::JwtParser;
use key_management::api::{CryptoOperations, DefaultCryptoImpl};
use log::{error};
use rdb::get_connection;
use sea_orm::{DatabaseConnection, TransactionTrait};
use serde_json::{from_str, from_value};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::pin::Pin;
use std::sync::Arc;
use config_manager::types::CONFIG;

pub struct RvMysqlImpl;

impl RvMysqlImpl {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl RefValueTrait for RvMysqlImpl {
    async fn add(&self, conn: Data<Arc<DatabaseConnection>>, rv_model: &RefValueModel) -> Result<(), RefValueError> {
        let raw_conn: &DatabaseConnection = &**conn;
        match RvDbRepo::add(raw_conn, rv_model, 100).await {
            Ok(_) => {
                let txn = conn.begin().await.map_err(|e| DbError(e.to_string()))?;
                RvDtlDbRepo::add(&txn, rv_model).await?;
                txn.commit().await.map_err(|e| DbError(e.to_string()))?;
                Ok(())
            }
            Err(e) => {
                error!("Ref value added failed: {}", e);
                Err(e)
            }
        }
    }

    async fn update(
        &self,
        conn: Data<Arc<DatabaseConnection>>,
        user_id: &str,
        update_req_body: &RvUpdateReqBody,
    ) -> Result<(i32, String), RefValueError> {
        let txn = conn.begin().await.map_err(|e| DbError(e.to_string()))?;
        let (version, org_name, org_attester_type) = RvDbRepo::update(&txn, &user_id, &update_req_body.id, &update_req_body).await.map_err(|e| {
            error!("Reference value update failed: {}", e);
            e
        })?;
        let (is_name_changed, new_name) =
            update_req_body.name.as_ref().map(|name| (true, name.to_string())).unwrap_or((false, String::new()));

        let (is_attester_type_changed, new_attester_type) = update_req_body
            .attester_type
            .as_ref()
            .map(|attester_type| (true, attester_type.to_string()))
            .unwrap_or((false, String::new()));

        let (is_content_changed, new_content) = update_req_body
            .content
            .as_ref()
            .map(|content| (true, content.to_string()))
            .unwrap_or((false, String::new()));

        if is_attester_type_changed {
            RvDtlDbRepo::update_type_by_rv_id(&txn, user_id, &update_req_body.id, &new_attester_type).await?;
        }

        if is_content_changed {
            let mut details = Utils::parse_rv_detail_from_jwt_content(&new_content)?;
            details.set_all_ids(&update_req_body.id);
            details.set_uid(user_id);
            if is_attester_type_changed {
                details.set_attester_type(&new_attester_type);
            } else {
                details.set_attester_type(&org_attester_type);
            }

            RvDtlDbRepo::del_by_rv_ids(&txn, user_id, &vec![update_req_body.id.clone()]).await?;
            let chunks = details.reference_values.chunks(500);
            for chunk in chunks {
                RvDtlDbRepo::add_dtls(&txn, chunk.into()).await?;
            }
        }
        txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok((version, if is_name_changed { new_name } else { org_name }))
    }

    async fn delete(&self, conn: Data<Arc<DatabaseConnection>>, user_id: &str, del_type: &str, del_req_body: &RvDelReqBody) -> Result<(), RefValueError> {
        let del_req_body_clone = del_req_body.clone();
        match del_type {
            "all" => RvDbRepo::del_all(&conn, &user_id).await,
            "id" => {
                let txn = conn.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                RvDbRepo::del_by_id(&txn, &user_id, &del_req_body_clone.ids.clone().unwrap()).await?;
                RvDtlDbRepo::del_by_rv_ids(&txn, &user_id, &del_req_body_clone.ids.unwrap()).await?;
                txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                Ok(())
            }
            "type" => {
                let txn = conn.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                RvDbRepo::del_by_type(&conn, &user_id, &del_req_body_clone.attester_type.clone().unwrap()).await?;
                RvDtlDbRepo::del_by_attester_type(&txn, &user_id, &del_req_body_clone.attester_type.unwrap()).await?;
                txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                Ok(())
            }
            _ => Err(InvalidParameter(format!("Invalid delete_type: {}", del_req_body.delete_type))),
        }
    }

    fn verify<'a>(&'a self,
                  measurements: &'a Vec<String>,
                  user_id: &'a str,
                  attester_type: &'a str
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            let conn = match get_connection().await {
                Ok(conn) => conn,
                Err(e) => {
                    let error_msg = format!("Database connection failed: {}", e);
                    error!("{}", error_msg);
                    return Err(error_msg);
                }
            };

            let is_require_sign = match CONFIG.get_instance() {
                Ok(config) => config.attestation_service.key_management.is_require_sign,
                Err(e) => {
                    let error_msg = format!("Failed to get config instance: {}", e);
                    error!("{}", error_msg);
                    return Err(error_msg);
                }
            };

            // Clone the measurements to own them for the async block
            let measurements_ref: Vec<&str> = measurements.iter().map(|s| s.as_str()).collect();

            // Call the appropriate verification method based on configuration
            let result = if is_require_sign {
                // Verify with signature validation
                Self::verify_with_sign(&conn, measurements_ref, user_id, attester_type).await
            } else {
                // Verify without signature validation
                Self::verify_without_sign(&conn, measurements_ref, user_id, attester_type).await
            };

            Ok(result)
        })
    }
}

impl RvMysqlImpl {
    async fn verify_without_sign(
        conn: &DatabaseConnection,
        measurements: Vec<&str>,
        user_id: &str,
        attester_type: &str,
    ) -> Vec<String> {
        let measurements_set: HashSet<&str> = measurements.iter().copied().collect();
        let mut matched: HashSet<String> = HashSet::new();

        let mut page = 0;
        loop {
            let dtl_page = match RvDtlDbRepo::query_page_by_attester_type_and_uid(
                conn,
                attester_type,
                user_id,
                page,
                1000,
            )
                .await
            {
                Ok(page) => page,
                Err(e) => {
                    error!("Query failed on page {}: {}", page, e);
                    break;
                }
            };

            // 3. Handle empty page case
            if dtl_page.is_empty() {
                break;
            }

            // 4. Batch match measurements
            for dtl in dtl_page {
                if measurements_set.contains(dtl.sha256.as_str()) {
                    matched.insert(dtl.sha256);
                }
            }

            page += 1;
        }

        // 5. Calculate unmatched measurements
        let unmatched: Vec<String> =
            measurements.into_iter().filter(|m| !matched.contains(*m)).map(String::from).collect();

        unmatched
    }

    async fn verify_with_sign(
        conn: &DatabaseConnection,
        measurements: Vec<&str>,
        user_id: &str,
        attester_type: &str,
    ) -> Vec<String> {
        // 1. Pre-calculate measurement set
        let measurements_set: HashSet<&str> = measurements.iter().copied().collect();
        let mut matched = HashSet::new();

        // 2. Stream process paginated data
        let mut page = 0;
        loop {
             // 2.1 Get main table data page
            let rv_models =
                match RvDbRepo::query_page_by_attester_type_and_uid(conn, attester_type, user_id, page, 10).await {
                    Ok(models) => models,
                    Err(e) => {
                        error!("Query main table failed: {}", e);
                        break;
                    }
                };

            if rv_models.is_empty() {
                break;
            }

            // 2.2 Parallel verify signatures and filter invalid items
            let verified_models: Vec<_> = stream::iter(rv_models)
                .filter_map(|model| async move { Self::verify_sig(conn, model.clone()).await.then_some(model) })
                .collect()
                .await;

            // 2.3 Get valid ID set
            let valid_ids: Vec<_> = verified_models.iter().map(|m| m.id.as_str()).collect();

            // 2.4 Query details and calculate hash
            if let Ok(details) = RvDtlDbRepo::query_by_ids(conn, valid_ids).await {
                // Create a quick lookup table
                let sha256_set: HashSet<String> =
                    details.iter().map(|dtl| dtl.sha256.clone()).collect();

                let rv_hashes = Self::convert_rv_models_to_map(verified_models);
                let dtl_hashes = Self::convert_rv_dtls_to_map(details);

                for (rv_id, rv_hash) in rv_hashes {
                    if dtl_hashes.get(&rv_id) == Some(&rv_hash) {
                        for id in &sha256_set {
                            if measurements_set.contains(&id.as_str()) {
                                matched.insert(id.clone());
                            }
                        }
                    }
                }
            }

            page += 1;
        }

        // 3. Calculate unmatched items
        let unmatched = measurements.into_iter().filter(|m| !matched.contains(*m)).map(String::from).collect();

        unmatched
    }
    fn convert_rv_dtls_to_map(rv_dtls: Vec<RvDtlDbModel>) -> HashMap<String, u64> {
        let mut ori_map: HashMap<String, Vec<RefValueDetail>> = HashMap::new();
        for db_dtl in rv_dtls {
            let value = serde_json::json!({
                "fileName": db_dtl.file_name,
                "sha256": db_dtl.sha256,
            });
            let dtl: RefValueDetail = from_value(value).unwrap();
            let id = db_dtl.ref_value_id;
            if ori_map.contains_key(&id) {
                ori_map.get_mut(&id).unwrap().push(dtl);
            } else {
                ori_map.insert(id, vec![dtl]);
            }
        }
        ori_map
            .into_iter()
            .map(|(id, vec)| {
                let details = RefValueDetails { reference_values: vec };
                let mut hasher = DefaultHasher::new();
                details.hash(&mut hasher);
                (id, hasher.finish())
            })
            .collect()
    }

    fn convert_rv_models_to_map(rv_models: Vec<RvDbModel>) -> HashMap<String, u64> {
        rv_models
            .into_iter()
            .filter_map(|model| {
                let rv_content_str = match JwtParser::get_payload(&model.content) {
                    Ok(content) => content,
                    Err(e) => {
                        error!("Failed to parse RV content to JWT payload: {}", e);
                        return None;
                    }
                };

                let rv_content: RefValueDetails = match from_str(&rv_content_str) {
                    Ok(content) => content,
                    Err(e) => {
                        error!("Failed to parse RV content JSON: {}", e);
                        return None;
                    }
                };

                let mut hasher = DefaultHasher::new();
                rv_content.hash(&mut hasher);
                Some((model.id, hasher.finish()))
            })
            .collect()
    }

    async fn verify_sig(conn: &DatabaseConnection, model: RvDbModel) -> bool {
        let active_model: ActiveModel = model.into();
        let data = match Utils::encode_rv_db_model_to_bytes(active_model.clone().into()) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to query total page when verify measurements: {}", e);
                return false;
            }
        };
        match DefaultCryptoImpl
            .verify("FSK", Some(&active_model.key_version.unwrap()), data, active_model.signature.unwrap())
            .await
        {
            Ok(true) => true,
            Ok(false) => {
                let id = active_model.id.unwrap();
                let version = active_model.version.unwrap();
                let update_valid_code_model = ActiveModelBuilder::new().valid_code(1).build();
                if let Err(e) = RvDbRepo::update_by_id_and_version(conn, update_valid_code_model, &id, version).await {
                    error!("Failed to update invalid code by query: {}", e);
                };
                false
            }
            Err(e) => {
                error!("Failed to verify reference value: {}", e);
                false
            }
        }
    }
}
