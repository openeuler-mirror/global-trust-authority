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

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "T_REF_VALUE_DETAIL")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    #[sea_orm(column_type = "String(StringLen::N(36))")]
    pub uid: String,
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub attester_type: String,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub file_name: String,
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub sha256: String,
    #[sea_orm(column_type = "String(StringLen::N(32))")]
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