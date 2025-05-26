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

use chrono::Utc;
use serde::{Deserialize, Serialize};
use super::policy_db_model::Model;

// Policy struct, represents a policy object
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Policy id, uuid
pub struct Policy {
    pub id: String,
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// Policy content
    pub content: String,
    /// Applicable challenge plugin types
    pub attester_type: Vec<String>,
    /// Whether it's a default policy, defaults to false when unspecified
    pub is_default: bool,
    /// Policy version, increments by 1 by default when updated
    pub version: i32,
    /// Create time
    pub create_time: i64,
    /// Update time
    pub update_time: i64,
    /// Whether it's valid (0-valid, 1-invalid)
    pub valid_code: i8,
}


impl Policy {
    /// Create a new Policy instance
    pub fn new(
        id: String,
        name: String,
        description: String,
        content: String,
        attester_type: Vec<String>,
        is_default: Option<bool>,
    ) -> Self {
        let current_time = Utc::now().timestamp();

        Policy {
            id,
            name,
            description,
            content,
            attester_type,
            is_default: is_default.unwrap_or(false),
            version: 1,
            create_time: current_time,
            update_time: current_time,
            valid_code: 0,
        }
    }
    
    /// Convert Policy to JSON value containing all fields
    pub fn to_full_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id.to_string(),
            "name": self.name,
            "description": self.description,
            "content": &self.content,
            "attester_type": self.attester_type,
            "is_default": self.is_default,
            "version": self.version,
            "update_time": self.update_time,
            "valid_code": self.valid_code,
        })
    }
    
    /// Convert Policy to JSON value containing only basic fields
    pub fn to_base_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id.to_string(),
            "name": self.name,
            "attester_type": self.attester_type,
            "update_time": self.update_time,
        })
    }
}

impl From<Model> for Policy {
    fn from(model: Model) -> Self {
        let attester_type: Vec<String> = serde_json::from_value(model.attester_type)
            .unwrap_or_default();

        Policy {
            id: model.policy_id,
            name: model.policy_name,
            description: model.policy_description,
            content: model.policy_content,
            attester_type,
            is_default: model.is_default,
            version: model.policy_version,
            create_time: model.create_time,
            update_time: model.update_time,
            valid_code: model.valid_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn test_policy_new() {
        let name = "Test Policy".to_string();
        let description = "Test Description".to_string();
        let content = "Test Content".to_string();
        let attester_type = vec!["type1".to_string(), "type2".to_string()];
        let id = Uuid::new_v4().to_string();

        let policy = Policy::new(
            id,
            name.clone(),
            description.clone(),
            content.clone(),
            attester_type.clone(),
            Some(true)
        );

        assert_eq!(policy.name, name);
        assert_eq!(policy.description, description);
        assert_eq!(policy.content, content);
        assert_eq!(policy.attester_type, attester_type);
        assert!(policy.is_default);
        assert_eq!(policy.version, 1);
        assert_eq!(policy.valid_code, 0);
    }

    #[test]
    fn test_policy_json_conversion() {
        let policy = Policy {
            id: String::from(Uuid::new_v4()),
            name: "Test Policy".to_string(),
            description: "Test Description".to_string(),
            content: "Test Content".to_string(),
            attester_type: vec!["type1".to_string()],
            is_default: true,
            version: 1,
            create_time: 1234567890,
            update_time: 1234567890,
            valid_code: 0,
        };

        let full_json = policy.to_full_json();
        assert_eq!(full_json["name"], json!(policy.name));
        assert_eq!(full_json["description"], json!(policy.description));
        assert_eq!(full_json["content"], json!(policy.content));
        assert_eq!(full_json["attester_type"], json!(policy.attester_type));
        assert_eq!(full_json["is_default"], json!(policy.is_default));
        assert_eq!(full_json["version"], json!(policy.version));

        let base_json = policy.to_base_json();
        assert_eq!(base_json["name"], json!(policy.name));
        assert_eq!(base_json["attester_type"], json!(policy.attester_type));
        assert_eq!(base_json["update_time"], json!(policy.update_time));
        assert_eq!(base_json["valid_code"], json!(policy.valid_code));
        assert!(!base_json.as_object().unwrap().contains_key("description"));
    }

    #[test]
    fn test_from_model() {
        let model = Model {
            policy_id: Uuid::new_v4().to_string(),
            policy_name: "Test Policy".to_string(),
            policy_description: "Test Description".to_string(),
            policy_content: "Test Content".to_string(),
            is_default: true,
            policy_version: 1,
            create_time: Utc::now().timestamp(),
            update_time: Utc::now().timestamp(),
            user_id: String::new(),
            attester_type: json!(["type1", "type2"]),
            signature: Vec::new(),
            valid_code: 0,
            key_version: String::new(),
            product_name: String::new(),
            product_type: String::new(),
            board_type: String::new(),
        };

        let policy: Policy = model.clone().into();

        assert_eq!(policy.id, model.policy_id);
        assert_eq!(policy.name, model.policy_name);
        assert_eq!(policy.description, model.policy_description);
        assert_eq!(policy.content, model.policy_content);
        assert_eq!(policy.is_default, model.is_default);
        assert_eq!(policy.valid_code, model.valid_code);

        let expected_attester_type: Vec<String> = serde_json::from_value(model.attester_type).unwrap();
        assert_eq!(policy.attester_type, expected_attester_type);
    }
}