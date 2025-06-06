//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.7

use crate::key_manager::model::Version;
use sea_orm::entity::prelude::*;
use sea_orm::DatabaseTransaction;
use sea_orm::Statement;
use sea_orm::ConnectionTrait;
use common_log::{error, info};
use rdb::get_connection;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "key_manager_key_version")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub key_version: String,
    pub key_type: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub async fn get_current_key_version() -> Result<Version, DbErr> {
    info!("KeyManagerKeyVersion: Getting current key version");
    let db = get_connection().await.map_err(|_e| {
        error!("Failed to get database connection");
        DbErr::ConnectionAcquire
    })?;
    let db = db.as_ref();
    // let result = Entity::find().one(db).await?;
    let result = Entity::find().all(db).await?.first().cloned();
    result
        .map(|m| Version::new(&m.key_version))
        .ok_or(DbErr::RecordNotFound("No version".into()))
}

pub async fn update_key_version(
    new_version: String,
    tx: &DatabaseTransaction,
) -> Result<(), DbErr> {
    info!(
        "KeyManagerKeyVersion: Updating key version: {}",
        new_version
    );
    Entity::delete_many().exec(tx).await?;
    let stmt = Statement::from_sql_and_values(
        tx.get_database_backend(),
        "INSERT INTO key_manager_key_version (key_version, key_type) VALUES (?, ?)",
        vec![
            Value::String(Some(Box::new(new_version))),
            Value::String(Some(Box::new("FILE".to_string()))),
        ],
    );
    tx.execute(stmt).await?;
    Ok(())
}
