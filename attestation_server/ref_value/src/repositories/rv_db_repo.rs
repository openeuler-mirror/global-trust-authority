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

use crate::entities::db_model::rv_db_model::{
    ActiveModel, ActiveModelBuilder, Column, Entity, Model,
};
use crate::entities::db_model::rv_detail_db_model::{Column as RvDetailDbColumn, Entity as RvDetailDbEntity};
use crate::entities::inner_model::rv_model::RefValueModel;
use crate::entities::request_body::rv_update_req_body::RvUpdateReqBody;
use crate::error::ref_value_error::RefValueError;
use crate::repositories::repo_ext::RepoExt;
use crate::utils::utils::Utils;
use config_manager::types::CONFIG;
use key_management::api::{CryptoOperations, DefaultCryptoImpl};
use log::error;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{ColumnTrait, Condition, DatabaseTransaction, DbErr, TransactionTrait};
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, Statement};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RvDbRepo {}

impl RvDbRepo {
    pub async fn add<C>(
        db: &C,
        rv_model: &RefValueModel,
        rv_limit: u64,
    ) -> Result<(), RefValueError>
    where
        C: ConnectionTrait,
    {
        let rv_db_model = rv_model.clone().into();
        Self::add_rv(db, rv_db_model, rv_limit).await
    }

    pub async fn update<C>(
        db: &C,
        user_id: &str,
        id: &str,
        update_rv_body: &RvUpdateReqBody,
    ) -> Result<(i32, String, String), RefValueError>
    where
        C: ConnectionTrait,
    {
        let rv_update_model = ActiveModelBuilder::new()
            .id(&update_rv_body.id)
            .uid(&user_id)
            .op_name(&update_rv_body.name)
            .op_description(&update_rv_body.description)
            .op_attester_type(&update_rv_body.attester_type)
            .op_content(&update_rv_body.content)
            .op_is_default(update_rv_body.is_default)
            .update_time(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64)
            .build();

        let (version, org_name, org_attester_type) =
            match Self::update_rv(db, user_id, id, rv_update_model).await {
                Err(e) => return Err(e),
                Ok(res) => res,
            };
        Ok((version, org_name, org_attester_type))
    }

    /// Deletes all reference values and their details for a specific user
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user whose reference values should be deleted
    ///
    /// # Returns
    /// * `Ok(())` - If all reference values were successfully deleted
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to begin transaction
    /// * Failed to delete reference values
    /// * Failed to delete reference value details
    /// * Failed to commit transaction
    pub async fn del_all(db: &DatabaseConnection, user_id: &str) -> Result<(), RefValueError> {
        let txn = db.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        if let Err(e) = Entity::delete_many().filter(Column::Uid.eq(user_id)).exec(&txn).await {
            return Err(RefValueError::DbError(e.to_string()));
        };
        if let Err(e) = RvDetailDbEntity::delete_many().filter(RvDetailDbColumn::Uid.eq(user_id)).exec(&txn).await {
            return Err(RefValueError::DbError(e.to_string()));
        };
        txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    /// Deletes specific reference values by their IDs for a given user
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `user_id` - ID of the user who owns the reference values
    /// * `ids` - Vector of reference value IDs to delete
    ///
    /// # Returns
    /// * `Ok(())` - If all specified reference values were successfully deleted
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute delete query
    pub async fn del_by_id<C>(
        conn: &C,
        user_id: &str,
        ids: &Vec<String>,
    ) -> Result<(), RefValueError>
    where C: ConnectionTrait
    {
        Entity::delete_many()
            .filter(Column::Uid.eq(user_id).and(Column::Id.is_in(ids.clone())))
            .exec(conn)
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    /// Deletes all reference values of a specific attester type for a given user
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user who owns the reference values
    /// * `attester_type` - Type of attester whose reference values should be deleted
    ///
    /// # Returns
    /// * `Ok(())` - If all reference values of the specified type were successfully deleted
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute delete query
    pub async fn del_by_type(
        db: &DatabaseConnection,
        user_id: &str,
        attester_type: &str,
    ) -> Result<(), RefValueError> {
        Entity::delete_many()
            .filter(Column::Uid.eq(user_id).and(Column::AttesterType.eq(attester_type)))
            .exec(db)
            .await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    /// Retrieves all reference values for a specific user
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `user_id` - ID of the user whose reference values should be retrieved
    ///
    /// # Returns
    /// * `Ok(Vec<Model>)` - List of all reference value models for the user
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute database query
    pub async fn query_all(
        conn: &DatabaseConnection,
        user_id: &str,
    ) -> Result<Vec<Model>, RefValueError> {
        let condition = Condition::all().add(Column::Uid.eq(user_id));

        RepoExt::query_all::<Entity, Column>(
            conn,
            // todo need to define a new model here to receive return values
            vec![],
            condition,
            Column::CreateTime,
        )
        .await
        .map_err(|e| RefValueError::DbError(e.to_string()))
    }

    /// Retrieves all reference values for a specific user and attester type
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `user_id` - ID of the user whose reference values should be retrieved
    /// * `attester_type` - Type of attester to filter the reference values
    ///
    /// # Returns
    /// * `Ok(Vec<Model>)` - List of reference value models matching the criteria
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute database query
    pub async fn query_all_by_attester_type(
        conn: &DatabaseConnection,
        user_id: &str,
        attester_type: &str,
    ) -> Result<Vec<Model>, RefValueError> {
        let condition =
            Condition::all().add(Column::AttesterType.eq(attester_type)).add(Column::Uid.eq(user_id));

        RepoExt::query_all::<Entity, Column>(
            conn,
            // todo need to define a new model here to receive return values
            vec![],
            condition,
            Column::CreateTime,
        )
        .await
        .map_err(|e| RefValueError::DbError(e.to_string()))
    }

    /// Retrieves reference values by their IDs for a specific user, with optional signature verification
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `user_id` - ID of the user who owns the reference values
    /// * `ids` - Vector of reference value IDs to retrieve
    ///
    /// # Returns
    /// * `Ok(Vec<RefValueModel>)` - List of reference value models with verified signatures
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute database query
    /// * Failed to encode reference value for signature verification
    /// * Failed to verify signature
    pub async fn query_by_ids(
        conn: &DatabaseConnection,
        user_id: &str,
        ids: &Vec<String>,
    ) -> Result<Vec<RefValueModel>, RefValueError> {
        let condition = Condition::all().add(Column::Id.is_in(ids.clone())).add(Column::Uid.eq(user_id));
        let models = RepoExt::query_all::<Entity, Column>(
            conn,
            // todo need to define a new model here to receive return values
            vec![],
            condition,
            Column::CreateTime,
        )
        .await
        .map_err(|e| RefValueError::DbError(e.to_string()))?;

        let is_require_sign = CONFIG.get_instance().unwrap().attestation_service.key_management.is_require_sign;
        if !is_require_sign {
            return Ok(models.into_iter().map(|m| m.into()).collect());
        }
        let mut response: Vec<RefValueModel> = Vec::new();
        for model in models {
            let mut rv_db_model: ActiveModel = model.into();
            let rv_db_model_clone = rv_db_model.clone();
            let data = Utils::encode_rv_db_model_to_bytes(rv_db_model_clone.clone())?;
            match DefaultCryptoImpl
                .verify(
                    "FSK",
                    Some(&rv_db_model_clone.key_version.unwrap()),
                    data,
                    rv_db_model_clone.signature.unwrap(),
                )
                .await
            {
                Ok(true) => {},
                Ok(false) => {
                    let id = rv_db_model_clone.id.unwrap();
                    let version = rv_db_model_clone.version.unwrap();
                    let update_valid_code_model = ActiveModelBuilder::new().valid_code(1).build();
                    if let Err(e) = Self::update_by_id_and_version(conn, update_valid_code_model, &id, version).await
                    {
                        error!("Failed to update invalid code by query: {}", e);
                    };
                    rv_db_model.set_valid_code(Set(1));
                },
                Err(e) => {
                    error!("Failed to verify reference value: {}", e);
                    rv_db_model.set_valid_code(Set(1));
                },
            }
            response.push(rv_db_model.into());
        }
        Ok(response)
    }

    /// Counts the number of pages for reference values with a different key version
    ///
    /// # Arguments
    /// * `db` - Database transaction
    /// * `key_version` - Key version to compare against
    /// * `page_size` - Number of items per page
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of pages
    ///
    /// # Errors
    /// Returns `DbErr` when:
    /// * Failed to execute database query
    /// * Failed to count records
    pub async fn count_pages_by_key_version(
        db: &DatabaseTransaction,
        key_version: &str,
        page_size: u64,
    ) -> Result<u64, DbErr> {
        let condition = Condition::all().add(Column::KeyVersion.ne(key_version));

        RepoExt::count_pages_with_condition::<Entity, Column>(db, page_size, condition, Column::Id).await
    }

    /// Counts the number of pages for reference values by attester type and user ID
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `attester_type` - Type of attester to filter by
    /// * `uid` - User ID to filter by
    /// * `page_size` - Number of items per page
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of pages
    ///
    /// # Errors
    /// Returns `DbErr` when:
    /// * Failed to execute count query
    pub async fn count_pages_by_attester_type_and_uid(
        db: &DatabaseConnection,
        attester_type: &str,
        uid: &str,
        page_size: u64,
    ) -> Result<u64, DbErr> {
        let condition = Condition::all().add(Column::AttesterType.ne(attester_type)).add(Column::Uid.eq(uid));

        RepoExt::count_pages_with_condition::<Entity, Column>(db, page_size, condition, Column::Id).await
    }

    /// Queries a page of reference values filtered by attester type and user ID
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `attester_type` - Type of attester to filter by
    /// * `uid` - User ID to filter by
    /// * `page_num` - Page number to retrieve
    /// * `page_size` - Number of items per page
    ///
    /// # Returns
    /// * `Ok(Vec<Model>)` - List of reference value models for the specified page
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute pagination query
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
            // SELECT_COLUMNS_NEED_VERIFY_SIG.to_vec(),
            vec![],
            condition,
            Column::Id,
        )
        .await
        .map_err(|e| RefValueError::DbError(e.to_string()))
    }

    /// Queries a page of reference values with a different key version
    ///
    /// # Arguments
    /// * `txn` - Database transaction
    /// * `page_num` - Page number to retrieve
    /// * `page_size` - Number of items per page
    /// * `key_version` - Key version to compare against
    ///
    /// # Returns
    /// * `Ok(Vec<Model>)` - List of reference value models for the specified page
    ///
    /// # Errors
    /// Returns `DbErr` when:
    /// * Failed to execute pagination query
    pub async fn query_page_by_key_version(
        txn: &DatabaseTransaction,
        page_num: u64,
        page_size: u64,
        key_version: &str,
    ) -> Result<Vec<Model>, DbErr> {
        let condition = Condition::all().add(Column::KeyVersion.ne(key_version));

        RepoExt::query_with_pagination::<Entity, Column>(
            txn,
            page_num,
            page_size,
            // SELECT_COLUMNS_NEED_VERIFY_SIG.to_vec(),
            vec![],
            condition,
            Column::Id,
        )
        .await
    }

    /// Updates a reference value by its ID and version number
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `model` - Updated reference value model
    /// * `id` - ID of the reference value to update
    /// * `cur_version` - Current version number of the reference value
    ///
    /// # Returns
    /// * `Ok(())` - If the update was successful
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * Failed to execute update query
    /// * Reference value has been modified by another request
    pub async fn update_by_id_and_version<C>(
        conn: &C,
        model: ActiveModel,
        id: &str,
        cur_version: i32,
    ) -> Result<(), RefValueError>
    where
        C: ConnectionTrait,
    {
        let affected = Entity::update_many()
            .set(model)
            .filter(Column::Id.eq(id).and(Column::Version.eq(cur_version)))
            .exec(conn)
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?
            .rows_affected;

        if affected == 0 {
            return Err(RefValueError::DbError("Ref Value has been modified by another request, please retry".into()));
        }
        Ok(())
    }
}

impl RvDbRepo {
    async fn add_rv<C>(
        db: &C,
        rv_info: ActiveModel,
        rv_limit: u64,
    ) -> Result<(), RefValueError>
    where C: ConnectionTrait
    {
        let sql = r#"
            INSERT INTO T_REF_VALUE (
                id, name, uid, description, attester_type, content,
                is_default, version, create_time, update_time,
                valid_code, key_version, signature
            )
            WITH checks AS (
                SELECT COUNT(*) as count,
                       EXISTS(SELECT 1 FROM T_REF_VALUE WHERE uid = ? AND name = ?) as name_exists
                FROM T_REF_VALUE WHERE uid = ?
            )
            SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?
            FROM dual WHERE (SELECT count FROM checks) < ? AND (SELECT name_exists FROM checks) = false
        "#;

        let result = db
            .execute(Statement::from_sql_and_values(
                db.get_database_backend(),
                sql,
                vec![
                    rv_info.uid.clone().unwrap().into(),
                    rv_info.name.clone().unwrap().into(),
                    rv_info.uid.clone().unwrap().into(),
                    rv_info.id.clone().unwrap().into(),
                    rv_info.name.clone().unwrap().into(),
                    rv_info.uid.clone().unwrap().into(),
                    rv_info.description.clone().unwrap().into(),
                    rv_info.attester_type.clone().unwrap().into(),
                    rv_info.content.clone().unwrap().into(),
                    rv_info.is_default.clone().unwrap().into(),
                    rv_info.version.clone().unwrap().into(),
                    rv_info.create_time.clone().unwrap().into(),
                    rv_info.update_time.clone().unwrap().into(),
                    rv_info.valid_code.clone().unwrap().into(),
                    rv_info.key_version.clone().unwrap().into(),
                    rv_info.signature.clone().unwrap().into(),
                    rv_limit.into(),
                ],
            ))
            .await;

        match result {
            Ok(res) if res.rows_affected() > 0 => Ok(()),
            Ok(_) => Err(RefValueError::DbError(
                "User has reached the maximum number of reference values or name exists".into(),
            )),
            Err(e) if e.to_string().contains("unique constraint") => {
                Err(RefValueError::DbError("Reference value already exists".into()))
            },
            Err(e) => Err(RefValueError::DbError(e.to_string())),
        }
    }

    async fn update_rv<C>(
        conn: &C,
        user_id: &str,
        id: &str,
        mut db_model: ActiveModel,
    ) -> Result<(i32, String, String), RefValueError>
    where C: ConnectionTrait
    {
        let result = conn
            .query_one(Statement::from_sql_and_values(
                conn.get_database_backend(),
                "SELECT version, name, attester_type, is_default, content FROM T_REF_VALUE WHERE id = ? and uid = ?",
                [id.into(), user_id.into()],
            ))
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        let row = match result {
            Some(row) => row,
            None => return Err(RefValueError::DbError("id is not exist.".into())),
        };
        let version: i32 = row.try_get("", "version").map_err(|e| RefValueError::DbError(e.to_string()))?;
        let org_name: String = row.try_get("", "name").map_err(|e| RefValueError::DbError(e.to_string()))?;
        let org_attester_type: String =
            row.try_get("", "attester_type").map_err(|e| RefValueError::DbError(e.to_string()))?;
        let org_is_default: bool = row.try_get("", "is_default").map_err(|e| RefValueError::DbError(e.to_string()))?;
        let org_content: String = row.try_get("", "content").map_err(|e| RefValueError::DbError(e.to_string()))?;
        let new_version = version.checked_add(1).ok_or_else(|| 
            RefValueError::DbError("Version number overflow".into())
        )?;
        db_model.set_version(Set(new_version));
        if db_model.name.is_not_set() {
            db_model.set_name(Unchanged(org_name.clone()));
        }
        if db_model.attester_type.is_not_set() {
            db_model.set_attester_type(Unchanged(org_attester_type.clone()));
        }
        if db_model.content.is_not_set() {
            db_model.set_content(Unchanged(org_content));
        }
        if db_model.is_default.is_not_set() {
            db_model.set_is_default(Unchanged(org_is_default));
        }
        let is_require_sign = CONFIG.get_instance().unwrap().attestation_service.key_management.is_require_sign;
        if is_require_sign {
            let (signature, key_version) = Utils::sign_by_ref_value_db_model(db_model.clone()).await?;
            db_model.set_signature(Set(signature));
            db_model.set_key_version(Set(key_version));
        }
        Self::update_by_id_and_version(conn, db_model, id, version).await?;
        Ok((version + 1, org_name, org_attester_type))
    }
}
