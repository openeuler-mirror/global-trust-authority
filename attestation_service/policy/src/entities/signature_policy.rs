use serde::{Deserialize, Serialize};
use super::{policy::Policy, policy_db_model::Model};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_description: String,
    pub policy_content: String,
    pub policy_version: i32,
    pub key_version: String,
    pub attester_type: Vec<String>,
    pub is_default: bool,
    pub user_id: String,
    pub update_time: i64,
    pub create_time: i64,
    pub signature: Vec<u8>,
    pub valid_code: i8,
    pub product_name: String,
    pub product_type: String,
    pub board_type: String,
}

impl SignaturePolicy {

    pub fn encode_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        bytes.extend_from_slice(self.policy_id.as_bytes().as_ref());
        bytes.extend_from_slice(self.policy_name.as_bytes());
        bytes.extend_from_slice(self.policy_description.as_bytes());
        bytes.extend_from_slice(self.policy_content.as_bytes());
        bytes.extend_from_slice(&self.policy_version.to_le_bytes());
        for attester in &self.attester_type {
            bytes.extend_from_slice(attester.as_bytes());
        }
        bytes.extend_from_slice(&[self.is_default as u8]);
        bytes.extend_from_slice(self.user_id.as_bytes());
        bytes.extend_from_slice(&self.update_time.to_le_bytes());
        bytes.extend_from_slice(&self.create_time.to_le_bytes());
        bytes.extend_from_slice(self.product_name.as_bytes());
        bytes.extend_from_slice(self.product_type.as_bytes());
        bytes.extend_from_slice(self.board_type.as_bytes());
        bytes.extend_from_slice(&[self.valid_code as u8]);
        bytes
    }
}

impl From<Model> for SignaturePolicy {
    fn from(model: Model) -> Self {
        let attester_type: Vec<String> = serde_json::from_value(model.attester_type)
            .unwrap_or_default();

        SignaturePolicy {
            policy_id: model.policy_id,
            policy_name: model.policy_name,
            policy_description: model.policy_description,
            policy_content: model.policy_content,
            policy_version: model.policy_version,
            key_version: model.key_version,
            attester_type,
            is_default: model.is_default,
            user_id: model.user_id,
            update_time: model.update_time,
            create_time: model.create_time,
            signature: model.signature,
            valid_code: model.valid_code,
            product_name: model.product_name,
            product_type: model.product_type,
            board_type: model.board_type,
        }
    }
}

impl From<SignaturePolicy> for Policy {
    fn from(signature_policy: SignaturePolicy) -> Self {
        Policy {
            id: signature_policy.policy_id,
            name: signature_policy.policy_name,
            description: signature_policy.policy_description,
            content: signature_policy.policy_content,
            attester_type: signature_policy.attester_type,
            is_default: signature_policy.is_default,
            version: signature_policy.policy_version,
            create_time: signature_policy.create_time,
            update_time: signature_policy.update_time,
            valid_code: signature_policy.valid_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    fn create_test_signature_policy() -> SignaturePolicy {
        let now = Utc::now().timestamp();
        SignaturePolicy {
            policy_id: String::from(Uuid::new_v4()),
            policy_name: "Test Policy".to_string(),
            policy_description: "Test Description".to_string(),
            policy_content: "Test Content".to_string(),
            policy_version: 1,
            key_version: "key-1".to_string(),
            attester_type: vec!["type1".to_string(), "type2".to_string()],
            is_default: true,
            user_id: "user-1".to_string(),
            update_time: now,
            create_time: now,
            signature: vec![1, 2, 3],
            valid_code: 0,
            product_name: "product-1".to_string(),
            product_type: "type-1".to_string(),
            board_type: "board-1".to_string(),
        }
    }

    #[test]
    fn test_encode_to_bytes() {
        let policy = create_test_signature_policy();
        let bytes = policy.encode_to_bytes();

        // Verify bytes contains all the encoded fields
        assert!(bytes.len() > 0);
        assert!(bytes.starts_with(policy.policy_id.as_bytes()));

        // Convert bytes back to string for text fields verification
        let bytes_str = String::from_utf8_lossy(&bytes);
        assert!(bytes_str.contains(&policy.policy_name));
        assert!(bytes_str.contains(&policy.policy_description));
        assert!(bytes_str.contains(&policy.policy_content));
        assert!(bytes_str.contains(&policy.user_id));
        assert!(bytes_str.contains(&policy.product_name));
        assert!(bytes_str.contains(&policy.product_type));
        assert!(bytes_str.contains(&policy.board_type));

        // Verify boolean and numeric fields are included
        let is_default_byte = policy.is_default as u8;
        let valid_code_byte = policy.valid_code as u8;
        assert!(bytes.contains(&is_default_byte));
        assert!(bytes.contains(&valid_code_byte));
    }

    #[test]
    fn test_from_model() {
        let model = Model {
            policy_id: Uuid::new_v4().to_string(),
            policy_name: "Test Policy".to_string(),
            policy_description: "Test Description".to_string(),
            policy_content: "Test Content".to_string(),
            policy_version: 1,
            key_version: "key-1".to_string(),
            attester_type: json!(["type1", "type2"]),
            is_default: true,
            user_id: "user-1".to_string(),
            update_time: Utc::now().timestamp(),
            create_time: Utc::now().timestamp(),
            signature: vec![1, 2, 3],
            valid_code: 0,
            product_name: "product-1".to_string(),
            product_type: "type-1".to_string(),
            board_type: "board-1".to_string(),
        };

        let signature_policy: SignaturePolicy = model.clone().into();

        assert_eq!(signature_policy.policy_id, model.policy_id);
        assert_eq!(signature_policy.policy_name, model.policy_name);
        assert_eq!(signature_policy.policy_description, model.policy_description);
        assert_eq!(signature_policy.policy_content, model.policy_content);
        assert_eq!(signature_policy.policy_version, model.policy_version);
        assert_eq!(signature_policy.key_version, model.key_version);
        assert_eq!(signature_policy.is_default, model.is_default);
        assert_eq!(signature_policy.user_id, model.user_id);
        assert_eq!(signature_policy.update_time, model.update_time);
        assert_eq!(signature_policy.create_time, model.create_time);
        assert_eq!(signature_policy.signature, model.signature);
        assert_eq!(signature_policy.valid_code, model.valid_code);
        assert_eq!(signature_policy.product_name, model.product_name);
        assert_eq!(signature_policy.product_type, model.product_type);
        assert_eq!(signature_policy.board_type, model.board_type);

        let expected_attester_type: Vec<String> = serde_json::from_value(model.attester_type).unwrap();
        assert_eq!(signature_policy.attester_type, expected_attester_type);
    }

    #[test]
    fn test_to_policy() {
        let signature_policy = create_test_signature_policy();
        let policy: Policy = signature_policy.clone().into();

        assert_eq!(policy.id, signature_policy.policy_id);
        assert_eq!(policy.name, signature_policy.policy_name);
        assert_eq!(policy.description, signature_policy.policy_description);
        assert_eq!(policy.content, signature_policy.policy_content);
        assert_eq!(policy.attester_type, signature_policy.attester_type);
        assert_eq!(policy.is_default, signature_policy.is_default);
        assert_eq!(policy.create_time, signature_policy.create_time);
        assert_eq!(policy.update_time, signature_policy.update_time);
        assert_eq!(policy.valid_code, signature_policy.valid_code);
    }
}
