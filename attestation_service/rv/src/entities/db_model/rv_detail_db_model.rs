use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "T_REF_VALUE_DETAIL")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    #[sea_orm(column_type = String(36))]
    pub uid: String,
    #[sea_orm(column_type = String(64))]
    pub attester_type: String,
    #[sea_orm(column_type = String(255))]
    pub file_name: String,
    #[sea_orm(column_type = String(40))]
    pub sha256: String,
    #[sea_orm(column_type = String(32))]
    pub ref_value_id: String,
}

// Reserved enumeration for establishing table relationship
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Relation {
    // Directly panic when attempting to use associated table behavior
    pub fn related_entity() -> RelationDef {
        unimplemented!("Relationships not yet implemented for this entity")
    }
}

// Implemented default behavior for entity's ActiveModel
impl ActiveModelBehavior for ActiveModel {}