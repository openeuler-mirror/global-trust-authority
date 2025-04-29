use std::hash::{DefaultHasher, Hash, Hasher};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Serialize, Validate)]
pub struct RefValueDetails {
    #[serde(rename = "referenceValues")]
    pub reference_values: Vec<RefValueDetail>
}

impl Hash for RefValueDetails {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let sorted_values = self.reference_values.clone().sort();
        sorted_values.hash(state);
    }
}

impl RefValueDetails {
    pub fn set_all_ids(&mut self, ref_value_id: &str) {
        for detail in &mut self.reference_values {
            detail.set_ref_value_id(ref_value_id);
            detail.set_id();
        }
    }
    
    pub fn set_uid(&mut self, uid: &str) {
        for detail in &mut self.reference_values {
            detail.set_uid(uid);
        }
    }
    
    pub fn set_attester_type(&mut self, attester_type: &str) {
        for detail in &mut self.reference_values {
            detail.set_attester_type(attester_type);
        }
    }
}

#[derive(Deserialize, Serialize, Validate, PartialOrd, PartialEq, Ord, Eq, Clone)]
pub struct RefValueDetail {
    #[serde(skip)]
    pub id: String,
    #[serde(skip)]
    pub uid: String,
    #[serde(skip)]
    pub attester_type: String,
    #[serde(rename = "fileName")]
    #[validate(length(min = 1, max = 255))]
    pub file_name: String,
    #[validate(length(min = 1, max = 40))]
    pub sha256: String,
    #[serde(skip)]
    pub ref_value_id: String
}

impl RefValueDetail {
    pub fn set_ref_value_id(&mut self, ref_value_id: &str) {
        self.ref_value_id = ref_value_id.to_string();
    }
    pub fn set_id(&mut self) {
        let mut hasher = DefaultHasher::new();
        self.file_name.hash(&mut hasher);
        self.ref_value_id.hash(&mut hasher);
        let id = hasher.finish().to_string();
        self.id = id;
    }
    
    pub fn set_uid(&mut self, uid: &str) {
        self.uid = uid.to_string();
    }
    
    pub fn set_attester_type(&mut self, attester_type: &str) {
        self.attester_type = attester_type.to_string();
    }
}

