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

use crate::entities::db_model::rv_detail_db_model::{Column, Entity, Model};
use crate::entities::inner_model::rv_content::RefValueDetail;
use crate::entities::inner_model::rv_model::RefValueModel;
use crate::error::ref_value_error::RefValueError;
use crate::repositories::repo_ext::RepoExt;
use crate::utils::utils::Utils;
use sea_orm::QueryFilter;
use sea_orm::{ColumnTrait, Condition, DatabaseConnection, DbErr};
use sea_orm::{ConnectionTrait, DatabaseTransaction, EntityTrait, Statement};

pub struct RvDtlDbRepo {}

impl RvDtlDbRepo {
    /// Deletes reference value details by their reference value IDs
    ///
    /// # Arguments
    /// * `txn` - Database transaction reference
    /// * `user_id` - ID of the user who owns the reference values
    /// * `rv_ids` - Vector of reference value IDs whose details should be deleted
    ///
    /// # Returns
    /// * `Ok(())` - If all details were successfully deleted
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute delete query
    pub async fn del_by_rv_ids(txn: &DatabaseTransaction, user_id: &str, rv_ids: &Vec<String>) -> Result<(), RefValueError> {
        Entity::delete_many()
            .filter(Column::Uid.eq(user_id).and(Column::RefValueId.is_in(rv_ids.clone())))
            .exec(txn)
        .await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    /// Deletes all reference value details of a specific attester type
    ///
    /// # Arguments
    /// * `txn` - Database transaction reference
    /// * `user_id` - ID of the user who owns the reference values
    /// * `attester_type` - Type of attester whose details should be deleted
    ///
    /// # Returns
    /// * `Ok(())` - If all details were successfully deleted
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute delete query
    pub async fn del_by_attester_type(txn: &DatabaseTransaction, user_id: &str, attester_type: &str) -> Result<(), RefValueError> {
        Entity::delete_many()
            .filter(Column::Uid.eq(user_id).and(Column::AttesterType.eq(attester_type)))
            .exec(txn)
            .await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    /// Adds reference value details from a reference value model
    ///
    /// # Arguments
    /// * `txn` - Database transaction reference
    /// * `rv_model` - Reference value model containing the details to add
    ///
    /// # Returns
    /// * `Ok(())` - If all details were successfully added
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to parse JWT content
    /// * Failed to add details to database
    pub async fn add(txn: &DatabaseTransaction, rv_model: &RefValueModel) -> Result<(), RefValueError> {
        let mut details = Utils::parse_rv_detail_from_jwt_content(&rv_model.content)?;
        details.set_all_ids(&rv_model.id);
        details.set_uid(&rv_model.uid);
        details.set_attester_type(&rv_model.attester_type);
        let chunks = details.reference_values.chunks(500);
        for chunk in chunks {
            Self::add_dtls(txn, chunk.into()).await?;
        }
        Ok(())
    }

    /// Adds a batch of reference value details to the database
    ///
    /// # Arguments
    /// * `txn` - Database transaction reference
    /// * `dtl_values` - Vector of reference value details to add
    ///
    /// # Returns
    /// * `Ok(())` - If all details were successfully added
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute insert query
    pub async fn add_dtls(txn: &DatabaseTransaction, dtl_values: Vec<RefValueDetail>) -> Result<(), RefValueError> {
        let values = dtl_values
            .iter()
            .map(|d| {
                format!(
                    "('{}','{}','{}','{}','{}','{}')",
                    d.id, d.uid, d.attester_type, d.file_name, d.sha256, d.ref_value_id
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        txn.execute(Statement::from_string(
            txn.get_database_backend(),
            format!(
                "INSERT IGNORE INTO T_REF_VALUE_DETAIL(id,uid,attester_type,file_name,sha256,ref_value_id) VALUES {}",
                values
            ),
        ))
        .await
        .map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    /// Updates the attester type for all reference value details associated with a given ID
    ///
    /// # Arguments
    /// * `txn` - Database transaction reference
    /// * `uid` - User ID
    /// * `id` - Reference value ID
    /// * `attester_type` - New attester type to set
    ///
    /// # Returns
    /// * `Ok(())` - If the update was successful
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * `DbError` - If the database update operation fails
    pub async fn update_type_by_rv_id(
        txn: &DatabaseTransaction,
        uid: &str,
        id: &str,
        attester_type: &str,
    ) -> Result<(), RefValueError> {
        Entity::update_many()
            .col_expr(Column::AttesterType, attester_type.into())
            .filter(Column::RefValueId.eq(id).and(Column::Uid.eq(uid)))
            .exec(txn)
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    /// Queries reference value details by a list of reference value IDs
    ///
    /// # Arguments
    /// * `conn` - Database connection reference
    /// * `rv_ids` - Vector of reference value IDs to query
    ///
    /// # Returns
    /// * `Ok(Vec<Model>)` - List of reference value detail models matching the IDs
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * `DbError` - If the database query operation fails
    pub async fn query_by_ids(conn: &DatabaseConnection, rv_ids: Vec<&str>) -> Result<Vec<Model>, RefValueError> {
        let condition = Condition::all().add(Column::RefValueId.is_in(rv_ids));
        RepoExt::query_all::<Entity, Column>(conn, vec![], condition, Column::Id)
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))
    }

    /// Counts the total number of pages for reference value details filtered by attester type and user ID
    ///
    /// # Arguments
    /// * `conn` - Database connection reference
    /// * `attester_type` - Type of attester to filter by
    /// * `uid` - User ID to filter by
    /// * `page_size` - Number of items per page
    ///
    /// # Returns
    /// * `Ok(u64)` - Total number of pages
    ///
    /// # Errors
    /// Returns `DbErr` when:
    /// * Database connection fails
    /// * Count operation fails
    /// * Pagination calculation fails
    pub async fn count_pages_by_attester_type_and_uid(
        conn: &DatabaseConnection,
        attester_type: &str,
        uid: &str,
        page_size: u64,
    ) -> Result<u64, DbErr> {
        let condition = Condition::all().add(Column::AttesterType.eq(attester_type)).add(Column::Uid.eq(uid));

        RepoExt::count_pages_with_condition::<Entity, Column>(conn, page_size, condition, Column::Id).await
    }

    /// Queries a page of reference value details filtered by attester type and user ID
    ///
    /// # Arguments
    /// * `conn` - Database connection reference
    /// * `attester_type` - Type of attester to filter by
    /// * `uid` - User ID to filter by
    /// * `page_num` - Page number to retrieve
    /// * `page_size` - Number of items per page
    ///
    /// # Returns
    /// * `Ok(Vec<Model>)` - List of reference value detail models for the specified page
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * `DbError` - If the database query operation fails
    /// * Pagination parameters are invalid
    pub async fn query_page_by_attester_type_and_uid(
        conn: &DatabaseConnection,
        attester_type: &str,
        uid: &str,
        page_num: u64,
        page_size: u64,
    ) -> Result<Vec<Model>, RefValueError> {
        let condition = Condition::all().add(Column::AttesterType.eq(attester_type)).add(Column::Uid.eq(uid));
        RepoExt::query_with_pagination::<Entity, Column>(
            conn,
            page_num,
            page_size,
            // todo Only Sha256 needs to be checked here, optimization is required
            vec![],
            condition,
            Column::Id,
        )
        .await
        .map_err(|e| RefValueError::DbError(e.to_string()))
    }
}