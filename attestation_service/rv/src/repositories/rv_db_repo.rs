use crate::entities::db_model::rv_db_model::{
    ActiveModel as RvDbActiveModel, ActiveModelBuilder, Column as RvDbColumn, Entity as RvDbEntity, Model as RvDbModel,
};
use crate::entities::db_model::rv_detail_db_model::{Column as RvDetailDbColumn, Entity as RvDetailDbEntity};
use crate::entities::inner_model::rv_content::RefValueDetails;
use crate::entities::inner_model::rv_model::RefValueModel;
use crate::entities::request_body::rv_update_req_body::RvUpdateReqBody;
use crate::error::ref_value_error::RefValueError;
use crate::repositories::rv_dtl_db_repo::RvDtlDbRepo;
use crate::utils::utils::Utils;
use config_manager::types::CONFIG;
use key_management::api::{CryptoOperations, DefaultCryptoImpl};
use log::error;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{ColumnTrait, DatabaseTransaction, DbErr, PaginatorTrait, QueryOrder, QuerySelect, TransactionTrait};
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, Statement};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RvDbRepo {}

impl RvDbRepo {
    pub async fn add_ref_value(
        db: &DatabaseConnection,
        rv_model: &RefValueModel,
        rv_limit: u64,
    ) -> Result<(), RefValueError> {
        let rv_db_model = rv_model.clone().into();
        // todo: In exceptional scenarios, the main table may have data while the detail table has no data
        match Self::add_ref_value_main(db, rv_db_model, rv_limit).await {
            Ok(_) => {
                let txn = db.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                RvDtlDbRepo::add_ref_value_detail(&txn, &rv_model).await?;
                txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    pub async fn update_ref_value(
        db: &DatabaseConnection,
        user_id: &str,
        id: &str,
        update_rv_body: &RvUpdateReqBody,
    ) -> Result<(i32, String), RefValueError> {
        let txn = db.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        let (is_name_changed, new_name) =
            update_rv_body.name.as_ref().map(|name| (true, name.to_string())).unwrap_or((false, String::new()));

        let (is_attester_type_changed, new_attester_type) = update_rv_body
            .attester_type
            .as_ref()
            .map(|attester_type| (true, attester_type.to_string()))
            .unwrap_or((false, String::new()));

        let (is_content_changed, new_content) = update_rv_body
            .content
            .as_ref()
            .map(|content| (true, content.to_string()))
            .unwrap_or((false, String::new()));

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
            match Self::update_ref_value_main(&txn, user_id, id, rv_update_model).await {
                Err(e) => return Err(e),
                Ok(res) => res,
            };
        if is_attester_type_changed {
            if let Err(e) = RvDtlDbRepo::update_rv_detail_type_by_rv_id(&txn, user_id, id, &new_attester_type).await {
                return Err(e);
            }
        }
        if is_content_changed {
            let mut details = match Utils::parse_rv_detail_from_jwt_content(&new_content) {
                Ok(details) => details,
                Err(e) => return Err(e),
            };
            details.set_all_ids(id);
            details.set_uid(user_id);
            if is_attester_type_changed {
                details.set_attester_type(&new_attester_type);
            } else {
                details.set_attester_type(&org_attester_type);
            }

            if let Err(e) = RvDetailDbEntity::delete_many()
                .filter(RvDetailDbColumn::Uid.eq(user_id).and(RvDetailDbColumn::RefValueId.eq(id)))
                .exec(&txn)
                .await
            {
                return Err(RefValueError::DbError(e.to_string()));
            };

            if let Err(e) = RvDtlDbRepo::add_ref_value_details(&txn, &details).await {
                return Err(e);
            };
        }
        txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok((version, if is_name_changed { new_name } else { org_name }))
    }

    pub async fn del_all_ref_value(db: &DatabaseConnection, user_id: &str) -> Result<(), RefValueError> {
        let txn = db.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        if let Err(e) = RvDbEntity::delete_many().filter(RvDbColumn::Uid.eq(user_id)).exec(&txn).await {
            return Err(RefValueError::DbError(e.to_string()));
        };
        if let Err(e) = RvDetailDbEntity::delete_many().filter(RvDetailDbColumn::Uid.eq(user_id)).exec(&txn).await {
            return Err(RefValueError::DbError(e.to_string()));
        };
        txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn del_ref_value_by_id(
        db: &DatabaseConnection,
        user_id: &str,
        ids: &Vec<String>,
    ) -> Result<(), RefValueError> {
        let txn = db.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        if let Err(e) = RvDbEntity::delete_many()
            .filter(RvDbColumn::Uid.eq(user_id).and(RvDbColumn::Id.is_in(ids.clone())))
            .exec(&txn)
            .await
        {
            return Err(RefValueError::DbError(e.to_string()));
        };
        if let Err(e) = RvDetailDbEntity::delete_many()
            .filter(RvDetailDbColumn::Uid.eq(user_id).and(RvDetailDbColumn::RefValueId.is_in(ids.clone())))
            .exec(&txn)
            .await
        {
            return Err(RefValueError::DbError(e.to_string()));
        };
        txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn del_ref_value_by_type(
        db: &DatabaseConnection,
        user_id: &str,
        attester_type: &str,
    ) -> Result<(), RefValueError> {
        let txn = db.begin().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        if let Err(e) = RvDbEntity::delete_many()
            .filter(RvDbColumn::Uid.eq(user_id).and(RvDbColumn::AttesterType.eq(attester_type)))
            .exec(db)
            .await
        {
            return Err(RefValueError::DbError(e.to_string()));
        };
        if let Err(e) = RvDetailDbEntity::delete_many()
            .filter(RvDetailDbColumn::Uid.eq(user_id).and(RvDetailDbColumn::AttesterType.eq(attester_type)))
            .exec(db)
            .await
        {
            return Err(RefValueError::DbError(e.to_string()));
        };
        txn.commit().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn query_all_ref_value_ids(
        db: &DatabaseConnection,
        user_id: &str,
    ) -> Result<Vec<RvDbModel>, RefValueError> {
        let res = RvDbEntity::find()
            .select_only()
            .column(RvDbColumn::Id)
            .column(RvDbColumn::Name)
            .column(RvDbColumn::AttesterType)
            .filter(RvDbColumn::Uid.eq(user_id))
            .order_by_asc(RvDbColumn::CreateTime)
            .into_model::<RvDbModel>()
            .all(db)
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(res)
    }

    pub async fn query_ref_value_by_ids(
        db: &DatabaseConnection,
        user_id: &str,
        ids: &Vec<String>,
    ) -> Result<Vec<RefValueModel>, RefValueError> {
        let models = RvDbEntity::find()
            .filter(RvDbColumn::Id.is_in(ids.clone()).and(RvDbColumn::Uid.eq(user_id)))
            .order_by_asc(RvDbColumn::CreateTime)
            .into_model::<RvDbModel>()
            .all(db)
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        let is_require_sign = CONFIG.get_instance().unwrap().attestation_service.key_management.is_require_sign;
        if !is_require_sign {
            return Ok(models.into_iter().map(|m| m.into()).collect());
        }
        let mut response: Vec<RefValueModel> = Vec::new();
        for model in models {
            let mut rv_db_model: RvDbActiveModel = model.into();
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
                    if let Err(e) =
                        Self::update_rv_main_by_id_and_version(db, update_valid_code_model, &id, version).await
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

    pub async fn query_page_ref_value_by_attester_type_and_uid(
        conn: &DatabaseConnection,
        attester_type: &str,
        uid: &str,
        page_num: u64,
        page_size: u64,
    ) -> Result<Vec<RvDbModel>, RefValueError> {
        RvDbEntity::find()
            .select_only()
            .column(RvDbColumn::Id)
            .column(RvDbColumn::Uid)
            .column(RvDbColumn::Name)
            .column(RvDbColumn::AttesterType)
            .column(RvDbColumn::Content)
            .column(RvDbColumn::IsDefault)
            .column(RvDbColumn::KeyVersion)
            .column(RvDbColumn::Signature)
            .column(RvDbColumn::Version)
            .filter(RvDbColumn::AttesterType.ne(attester_type).and(RvDbColumn::Uid.eq(uid)))
            .order_by_asc(RvDbColumn::Id)
            .paginate(conn, page_size)
            .fetch_page(page_num)
            .await.map_err(|e| RefValueError::DbError(e.to_string()))
    }

    pub async fn query_ref_value_ids_by_attester_type(
        db: &DatabaseConnection,
        user_id: &str,
        attester_type: &str,
    ) -> Result<Vec<RvDbModel>, RefValueError> {
        let res = RvDbEntity::find()
            .select_only()
            .column(RvDbColumn::Id)
            .column(RvDbColumn::Name)
            .column(RvDbColumn::AttesterType)
            .filter(RvDbColumn::AttesterType.eq(attester_type).and(RvDbColumn::Uid.eq(user_id)))
            .order_by_asc(RvDbColumn::CreateTime)
            .into_model::<RvDbModel>()
            .all(db)
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(res)
    }

    pub async fn query_ref_value_total_pages_by_key_version(
        db: &DatabaseTransaction,
        key_version: &str,
        page_size: u64,
    ) -> Result<u64, DbErr> {
        RvDbEntity::find()
            .filter(RvDbColumn::KeyVersion.ne(key_version))
            .order_by_asc(RvDbColumn::Id)
            .paginate(db, page_size)
            .num_pages()
            .await
    }

    pub async fn query_rv_total_pages_by_attester_type_and_uid(
        db: &DatabaseConnection,
        attester_type: &str,
        uid: &str,
        page_size: u64,
    ) -> Result<u64, DbErr> {
        RvDbEntity::find()
            .filter(RvDbColumn::AttesterType.ne(attester_type).and(RvDbColumn::Uid.eq(uid)))
            .order_by_asc(RvDbColumn::Id)
            .paginate(db, page_size)
            .num_pages()
            .await
    }

    pub async fn query_page_ref_value_by_key_version(
        txn: &DatabaseTransaction,
        page_num: u64,
        page_size: u64,
        key_version: &str,
    ) -> Result<Vec<RvDbModel>, DbErr> {
        RvDbEntity::find()
            .select_only()
            .column(RvDbColumn::Id)
            .column(RvDbColumn::Uid)
            .column(RvDbColumn::Name)
            .column(RvDbColumn::AttesterType)
            .column(RvDbColumn::Content)
            .column(RvDbColumn::IsDefault)
            .column(RvDbColumn::KeyVersion)
            .column(RvDbColumn::Signature)
            .column(RvDbColumn::Version)
            .filter(RvDbColumn::KeyVersion.ne(key_version))
            .order_by_asc(RvDbColumn::Id)
            .paginate(txn, page_size)
            .fetch_page(page_num)
            .await
    }

    pub async fn update_rv_main_by_id_and_version<C>(
        conn: &C,
        model: RvDbActiveModel,
        id: &str,
        cur_version: i32,
    ) -> Result<(), RefValueError>
    where
        C: ConnectionTrait,
    {
        let affected = RvDbEntity::update_many()
            .set(model)
            .filter(RvDbColumn::Id.eq(id).and(RvDbColumn::Version.eq(cur_version)))
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
    async fn add_ref_value_main(
        db: &DatabaseConnection,
        rv_info: RvDbActiveModel,
        rv_limit: u64,
    ) -> Result<(), RefValueError> {
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

    async fn update_ref_value_main(
        db: &DatabaseTransaction,
        user_id: &str,
        id: &str,
        mut db_model: RvDbActiveModel,
    ) -> Result<(i32, String, String), RefValueError> {
        let result = db
            .query_one(Statement::from_sql_and_values(
                db.get_database_backend(),
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
        db_model.set_version(Set(version + 1));
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
        Self::update_rv_main_by_id_and_version(db, db_model, id, version).await?;
        Ok((version, org_name, org_attester_type))
    }
}
