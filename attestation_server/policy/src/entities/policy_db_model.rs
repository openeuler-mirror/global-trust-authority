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
use sea_orm::ActiveValue::Set;
use serde_json::Value;
use crate::entities::policy::Policy;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_information")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub policy_id: String,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub policy_name: String,
    #[sea_orm(column_type = "String(StringLen::N(512))")]
    pub policy_description: String,
    #[sea_orm(column_type = "Text")]
    pub policy_content: String,
    pub is_default: bool,
    pub policy_version: i32,
    pub create_time: i64,
    pub update_time: i64,
    #[sea_orm(indexed, column_type = "String(StringLen::N(36))")]
    pub user_id: String,
    #[sea_orm(column_type = "Json")]
    pub attester_type: Value,
    #[sea_orm(column_type = "Binary(512)")]
    pub signature: Vec<u8>,
    pub valid_code: i8,
    #[sea_orm(column_type = "String(StringLen::N(36))")]
    pub key_version: String,
    #[sea_orm(column_type = "String(StringLen::N(128))")]
    pub product_name: String,
    #[sea_orm(column_type = "String(StringLen::N(128))")]
    pub product_type: String,
    #[sea_orm(column_type = "String(StringLen::N(128))")]
    pub board_type: String,
}

// Reserved enumeration for establishing table relationship
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Relation {
    /// Directly panic when attempting to use associated table behavior
    /// 
    /// # Returns
    /// 
    /// * `panic` - Panic
    pub fn related_entity() -> RelationDef {
        panic!("Associated table behavior not realized")
    }
}

// Implemented default behavior for entity's ActiveModel
impl ActiveModelBehavior for ActiveModel {}

impl From<Policy> for ActiveModel {
    fn from(policy: Policy) -> Self {
        let attester_type = serde_json::to_value(policy.attester_type)
            .unwrap_or(Value::Array(vec![]));

        ActiveModel {
            policy_id: Set(policy.id.to_string()),
            policy_name: Set(policy.name),
            policy_description: Set(policy.description),
            policy_content: Set(policy.content),
            is_default: Set(policy.is_default),
            policy_version: Set(policy.version),
            create_time: Set(policy.create_time),
            update_time: Set(policy.update_time),
            user_id: Set(String::new()),
            attester_type: Set(attester_type),
            signature: Set(Vec::new()),
            valid_code: Set(0),
            key_version: Set(String::new()),
            product_name: Set(String::new()),
            product_type: Set(String::new()),
            board_type: Set(String::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_from_policy_to_active_model() {
        let policy = Policy {
            id: String::from(Uuid::new_v4()),
            name: "Test Policy".to_string(),
            description: "Test Description".to_string(),
            content: "Test Content".to_string(),
            attester_type: vec!["type1".to_string(), "type2".to_string()],
            is_default: true,
            version: 1,
            create_time: 1234567890,
            update_time: 1234567890,
            valid_code: 0,
        };

        let active_model: ActiveModel = policy.clone().into();

        assert_eq!(active_model.policy_id.unwrap(), policy.id.to_string());
        assert_eq!(active_model.policy_name.unwrap(), policy.name);
        assert_eq!(active_model.policy_description.unwrap(), policy.description);
        assert_eq!(active_model.policy_content.unwrap(), policy.content);
        assert_eq!(active_model.is_default.unwrap(), policy.is_default);
        assert_eq!(active_model.policy_version.unwrap(), policy.version);
        assert_eq!(active_model.valid_code.unwrap(), policy.valid_code);
        let attester_type: Vec<String> = serde_json::from_value(active_model.attester_type.unwrap()).unwrap();
        assert_eq!(attester_type, policy.attester_type);
        assert_eq!(active_model.user_id.unwrap(), String::new());
        assert_eq!(active_model.key_version.unwrap(), String::new());
        assert_eq!(active_model.product_name.unwrap(), String::new());
        assert_eq!(active_model.product_type.unwrap(), String::new());
        assert_eq!(active_model.board_type.unwrap(), String::new());
    }
}