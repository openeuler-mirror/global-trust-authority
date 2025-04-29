use actix_web::http::header::q;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, PaginatorTrait, QueryOrder, QuerySelect};
use sea_orm::QueryFilter;
use sea_orm::{ConnectionTrait, DatabaseTransaction, EntityTrait, Statement};
use crate::entities::inner_model::rv_content::RefValueDetails;
use crate::entities::inner_model::rv_model::RefValueModel;
use crate::error::ref_value_error::RefValueError;
use crate::utils::utils::Utils;
use crate::entities::db_model::rv_detail_db_model::{Column, Entity, Model};

pub struct RvDtlDbRepo {}

impl RvDtlDbRepo {
   pub async fn add_ref_value_detail(txn: &DatabaseTransaction, rv_model: &RefValueModel) -> Result<(), RefValueError> {
        let mut details = Utils::parse_rv_detail_from_jwt_content(&rv_model.content)?;
        details.set_all_ids(&rv_model.id);
        details.set_uid(&rv_model.uid);
        details.set_attester_type(&rv_model.attester_type);
        Self::add_ref_value_details(txn, &details).await?;
        Ok(())
    }

    pub async fn add_ref_value_details(txn: &DatabaseTransaction, details: &RefValueDetails) -> Result<(), RefValueError> {
        let values = details
            .reference_values
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
                "INSERT INTO T_REF_VALUE_DETAIL(id,uid,attester_type,file_name,sha256,ref_value_id) VALUES {}",
                values
            ),
        ))
            .await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn update_rv_detail_type_by_rv_id(
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
    
    pub async fn query_rv_details_by_ids(conn: &DatabaseConnection, rv_ids: Vec<&str>) -> Result<Vec<Model>, RefValueError> {
        Entity::find()
            .select_only()
            .column(Column::FileName)
            .column(Column::Sha256)
            .column(Column::RefValueId)
            .filter(Column::Id.is_in(rv_ids))
            .all(conn)
            .await.map_err(|e| RefValueError::DbError(e.to_string()))
    }

    pub async fn query_rv_dtl_total_pages_by_attester_type_and_uid(
        db: &DatabaseConnection,
        attester_type: &str,
        uid: &str,
        page_size: u64,
    ) -> Result<u64, DbErr> {
        Entity::find()
            .filter(Column::AttesterType.ne(attester_type).and(Column::Uid.eq(uid)))
            .order_by_asc(crate::entities::db_model::rv_db_model::Column::Id)
            .paginate(db, page_size)
            .num_pages()
            .await
    }

    pub async fn query_page_rv_dtl_by_attester_type_and_uid(
        conn: &DatabaseConnection,
        attester_type: &str,
        uid: &str,
        page_num: u64,
        page_size: u64,
    ) -> Result<Vec<Model>, RefValueError> {
        Entity::find()
            .select_only()
            .column(Column::Sha256)
            .filter(Column::AttesterType.ne(attester_type).and(Column::Uid.eq(uid)))
            .order_by_asc(Column::Id)
            .paginate(conn, page_size)
            .fetch_page(page_num)
            .await.map_err(|e| RefValueError::DbError(e.to_string()))
    }
}