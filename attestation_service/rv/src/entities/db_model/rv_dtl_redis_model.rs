use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RvRedisModel {
    pub sha256: String,
    pub user_id: String,
    pub attester_type: String,
    pub rv_id: String,
    pub file_name: String,
}

pub struct RvRedisModelBuilder{
    pub sha256: String,
    pub user_id: String,
    pub attester_type: String,
    pub rv_id: String,
    pub file_name: String,
}

impl RvRedisModelBuilder {
    pub fn new() -> Self {
        RvRedisModelBuilder {
            user_id: "".to_string(),
            attester_type: "".to_string(),
            rv_id: "".to_string(),
            file_name: "".to_string(),
            sha256: "".to_string(),
        }
    }
    
    pub fn user_id(mut self, user_id: &str) -> Self {
        self.user_id = user_id.to_string();
        self
    }
    
    pub fn attester_type(mut self, attester_type: &str) -> Self {
        self.attester_type = attester_type.to_string();
        self
    }
    
    pub fn rv_id(mut self, rv_id: &str) -> Self {
        self.rv_id = rv_id.to_string();
        self
    }
    
    pub fn file_name(mut self, file_name: &str) -> Self {
        self.file_name = file_name.to_string();
        self
    }
    
    pub fn sha256(mut self, sha256: &str) -> Self {
        self.sha256 = sha256.to_string();
        self
    }
    
    pub fn build(self) -> RvRedisModel {
        RvRedisModel {
            user_id: self.user_id,
            attester_type: self.attester_type,
            rv_id: self.rv_id,
            file_name: self.file_name,
            sha256: self.sha256,
        }
    }
}