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

use std::time::{SystemTime, UNIX_EPOCH};
use sea_orm::entity::prelude::*;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveValue, NotSet};
use serde::Serialize;
use crate::entities::inner_model::rv_model::RefValueModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "T_REF_VALUE")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    #[sea_orm(column_type = "String(StringLen::N(36))")]
    pub uid: String,
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub name: String,
    #[sea_orm(column_type = "String(StringLen::N(32))")]
    pub description: String,
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub attester_type: String,
    #[sea_orm(column_type = "Text")]
    pub content: String,
    pub is_default: bool,
    pub create_time: i64,
    pub update_time: i64,
    pub version: i32,

    #[sea_orm(column_type = "Binary(512)")]
    pub signature: Vec<u8>,
    #[sea_orm(column_type = "String(StringLen::N(36))")]
    pub key_version: String,
    pub valid_code: i8,
}

impl ActiveModel {
    pub fn set_version(&mut self, version: ActiveValue<i32>) {
        self.version = version;
    }
    
    pub fn set_name(&mut self, name: ActiveValue<String>) {
        self.name = name;
    }
    
    pub fn set_attester_type(&mut self, attester_type: ActiveValue<String>) {
        self.attester_type = attester_type;
    }
    
    pub fn set_content(&mut self, content: ActiveValue<String>) {
        self.content = content;
    }
    
    pub fn set_is_default(&mut self, is_default: ActiveValue<bool>) {
        self.is_default = is_default;
    }
    
    pub fn set_signature(&mut self, signature: ActiveValue<Vec<u8>>) {
        self.signature = signature;
    }
    
    pub fn set_key_version(&mut self, key_version: ActiveValue<String>) {
        self.key_version = key_version;
    }
    
    pub fn set_valid_code(&mut self, valid_code: ActiveValue<i8>) {
        self.valid_code = valid_code;
    }
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

impl From<RefValueModel> for ActiveModel {
    fn from(model: RefValueModel) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        
        ActiveModelBuilder::new()
            .id(&model.id)
            .uid(&model.uid)
            .name(&model.name)
            .description(&model.description)
            .attester_type(&model.attester_type)
            .content(&model.content)
            .is_default(model.is_default)
            .create_time(now)
            .update_time(now)
            .signature(&model.signature)
            .key_version(&model.key_version)
            .version(model.version)
            .valid_code(model.valid_code)
            .build()
    }
}

pub struct ActiveModelBuilder {
    id: ActiveValue<String>,
    uid: ActiveValue<String>,
    name: ActiveValue<String>,
    description: ActiveValue<String>,
    attester_type: ActiveValue<String>,
    content: ActiveValue<String>,
    is_default: ActiveValue<bool>,
    create_time: ActiveValue<i64>,
    update_time: ActiveValue<i64>,
    version: ActiveValue<i32>,
    signature: ActiveValue<Vec<u8>>,
    key_version: ActiveValue<String>,
    valid_code: ActiveValue<i8>,
}
impl ActiveModelBuilder {
    pub fn new() -> Self {
        ActiveModelBuilder{
            id: NotSet,
            uid: NotSet,
            name: NotSet,
            description: NotSet,
            attester_type: NotSet,
            content: NotSet,
            is_default: NotSet,
            create_time: NotSet,
            update_time: NotSet,
            version: NotSet,
            signature: NotSet,
            key_version: NotSet,
            valid_code: NotSet,
        }
    }
    
    pub fn id(mut self, id: &str) -> Self {
        self.id = Set(id.to_string());
        self
    }
    
    pub fn uid(mut self, uid: &str) -> Self {
        self.uid = Set(uid.to_string());
        self
    }
    
    pub fn name(mut self, name: &str) -> Self {
        self.name = Set(name.to_string());
        self
    }
    
    pub fn op_name(mut self, name: &Option<String>) -> Self {
        match name {
            Some(name) => self.name = Set(name.clone()),
            None => {},
        }
        self
    }
    
    pub fn description(mut self, description: &str) -> Self {
        self.description = Set(description.to_string());
        self
    }
    
    pub fn op_description(mut self, description: &Option<String>) -> Self {
        match description {
            Some(description) => self.description = Set(description.clone()),
            None => {},
        }
        self
    }
    
    pub fn attester_type(mut self, attester_type: &str) -> Self {
        self.attester_type = Set(attester_type.to_string());
        self
    }
    
    pub fn op_attester_type(mut self, attester_type: &Option<String>) -> Self {
        match attester_type {
            Some(attester_type) => self.attester_type = Set(attester_type.clone()),
            None => {},
        }
        self
    }
    
    pub fn content(mut self, content: &str) -> Self {
        self.content = Set(content.to_string());
        self
    }
    
    pub fn op_content(mut self, content: &Option<String>) -> Self {
        match content {
            Some(content) => self.content = Set(content.clone()),
            None => {},
        }
        self
    }
    
    pub fn is_default(mut self, is_default: bool) -> Self {
        self.is_default = Set(is_default);
        self
    }
    
    pub fn op_is_default(mut self, is_default: Option<bool>) -> Self {
        match is_default {
            Some(is_default) => self.is_default = Set(is_default),
            None => {},
        }
        self
    }
    
    pub fn create_time(mut self, create_time: i64) -> Self {
        self.create_time = Set(create_time);
        self
    }
    
    pub fn update_time(mut self, update_time: i64) -> Self {
        self.update_time = Set(update_time);
        self
    }
    
    pub fn version(mut self, version: i32) -> Self {
        self.version = Set(version);
        self
    }
    
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Set(signature.to_vec());
        self
    }
    
    pub fn op_signature(mut self, signature: Option<Vec<u8>>) -> Self {
        match signature {
            Some(signature) => self.signature = Set(signature),
            None => {},
        }
        self
    }
    
    pub fn key_version(mut self, key_version: &str) -> Self {
        self.key_version = Set(key_version.to_string());
        self
    }
    
    pub fn op_key_version(mut self, key_version: Option<String>) -> Self {
        match key_version {
            Some(key_version) => self.key_version = Set(key_version),
            None => {},
        }
        self
    }
    
    pub fn valid_code(mut self, valid_code: i8) -> Self {
        self.valid_code = Set(valid_code);
        self
    }
    
    pub fn build(self) -> ActiveModel {
        ActiveModel {
            id: self.id,
            uid: self.uid,
            name: self.name,
            description: self.description,
            attester_type: self.attester_type,
            content: self.content,
            is_default: self.is_default,
            create_time: self.create_time,
            update_time: self.update_time,
            version: self.version,
            signature: self.signature,
            key_version: self.key_version,
            valid_code: self.valid_code,
        }
    }
}