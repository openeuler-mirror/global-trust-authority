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

use serde::Serialize;
use crate::entities::db_model::rv_db_model::{ActiveModel, Model};

#[derive(Clone, Serialize)]
pub struct RefValueModel {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub description: String,
    pub attester_type: String,
    pub content: String,
    pub is_default: bool,
    #[serde(skip_serializing)]
    pub signature: Vec<u8>,
    #[serde(skip_serializing)]
    pub key_version: String,
    pub version: i32,
    pub valid_code: i8,
}

impl RefValueModel {
    pub fn set_signature(&mut self, signature: &Vec<u8>) {
        self.signature = signature.clone();
    }
    
    pub fn set_key_version(&mut self, key_version: &str) {
        self.key_version = key_version.to_string();
    }
}

impl From<Model> for RefValueModel {
    fn from(model: Model) -> Self {
        RefValueModel {
            id: model.id,
            uid: model.uid,
            name: model.name,
            description: model.description,
            attester_type: model.attester_type,
            content: model.content,
            is_default: model.is_default,
            signature: model.signature,
            key_version: model.key_version,
            version: model.version,
            valid_code: model.valid_code,
        }
    }
}

impl From<ActiveModel> for RefValueModel {
    fn from(model: ActiveModel) -> Self {
        RefValueModelBuilder::new()
            .id(model.id.as_ref())
            .uid(model.uid.as_ref())
            .name(model.name.as_ref())
            .description(model.description.as_ref())
            .attester_type(model.attester_type.as_ref())
            .content(model.content.as_ref())
            .is_default(*model.is_default.as_ref())
            .version(*model.version.as_ref())
            .valid_code(*model.valid_code.as_ref())
            .build()
    }
}

pub struct RefValueModelBuilder {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub description: String,
    pub attester_type: String,
    pub content: String,
    pub is_default: bool,
    pub version: i32,
    pub valid_code: i8,
}

impl RefValueModelBuilder {
    pub fn new() -> Self {
        RefValueModelBuilder {
            id: "".to_string(),
            uid: "".to_string(),
            name: "".to_string(),
            description: "".to_string(),
            attester_type: "".to_string(),
            content: "".to_string(),
            is_default: true,
            version: 0,
            valid_code: 0,
        }
    }
    
    pub fn id(mut self, id: &str) -> Self {
        self.id = id.to_string();
        self
    }
    
    pub fn uid(mut self, uid: &str) -> Self {
        self.uid = uid.to_string();
        self
    }
    
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }
    
    pub fn description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }
    
    pub fn op_description(mut self, description: &Option<String>) -> Self {
        match description {
            Some(desc) => self.description = desc.to_string(),
            None => {},
        }
        self
    }
    
    pub fn attester_type(mut self, attester_type: &str) -> Self {
        self.attester_type = attester_type.to_string();
        self
    }
    
    pub fn content(mut self, content: &str) -> Self {
        self.content = content.to_string();
        self
    }
    
    pub fn is_default(mut self, is_default: bool) -> Self {
        self.is_default = is_default;
        self
    }
    
    pub fn version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }
    
    pub fn valid_code(mut self, valid_code: i8) -> Self {
        self.valid_code = valid_code;
        self
    }
    
    pub fn build(self) -> RefValueModel {
        RefValueModel {
            id: self.id,
            uid: self.uid,
            name: self.name,
            description: self.description,
            attester_type: self.attester_type,
            content: self.content,
            is_default: self.is_default,
            signature: vec![],
            key_version: "".to_string(),
            version: self.version,
            valid_code: self.valid_code,
        }
    }
}