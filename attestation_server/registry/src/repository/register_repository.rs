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
pub mod register {
    use crate::{apikey::register, error::register_error::RegisterError};
    use base64::{engine::general_purpose, Engine};
    use sea_orm::{entity::prelude::*, ActiveValue::Set};
    use serde::Serialize;
    use zeroize::Zeroize;
    use common_log::{debug};

    #[derive(Clone, Debug, Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "t_apikey_info")]
    pub struct Model {
        #[sea_orm(column_name = "uid", primary_key, auto_increment=false)]
        pub uid: String,
        #[sea_orm(column_name = "hashed_key")]
        pub hashed_key: String,
        #[sea_orm(column_name = "salt")]
        pub salt: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    pub async fn select_data(uid: &str, db: &DatabaseConnection) -> Result<Model, RegisterError> {
        let key = Entity::find_by_id(uid.to_string())
            .one(db)
            .await?
            .ok_or(RegisterError::RecordNotFound(format!("uid: {}", uid)))?;
        Ok(key)
    }

    pub async fn update_data(info: &mut register::ApiKeyInfo, db: &DatabaseConnection) -> Result<(), RegisterError> {
        let model = Entity::find_by_id(info.uid.to_string())
            .one(db)
            .await?
            .ok_or(RegisterError::RecordNotFound(format!("uid: {}", info.uid)))?;

        let mut active_model: ActiveModel = model.into();
        active_model.hashed_key = Set(general_purpose::STANDARD.encode(&info.hashed_key));
        info.hashed_key.zeroize();
        active_model.update(db).await?;
        Ok(())
    }

    pub async fn insert_data(info: &mut register::ApiKeyInfo, db: &DatabaseConnection) -> Result<(), RegisterError> {
        let active_model = ActiveModel {
            uid: Set(info.uid.to_string()),
            hashed_key: Set(general_purpose::STANDARD.encode(&info.hashed_key)),
            salt: Set(general_purpose::STANDARD.encode(&info.salt)),
            ..Default::default()
        };
        info.salt.zeroize();
        info.hashed_key.zeroize();
        match Entity::insert(active_model).exec(db).await {
            Ok(result) => {
                debug!("insert data success {:?}", result);
                Ok(())
            },
            Err(err) => {
                Err(RegisterError::DbError(format!("insert data error: {:?}", err)))
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::apikey::register::ApiKeyInfo;
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, MockExecResult};
    use base64::Engine;
    use base64::engine::general_purpose;
    use crate::error::register_error::RegisterError;

    #[tokio::test]
    async fn test_select_data_success() {
        let uid = "test_uid";
        let expected_model = register::Model {
            uid: uid.to_string(),
            hashed_key: "hashed_key_encoded".to_string(),
            salt: "salt_encoded".to_string(),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![expected_model.clone()]])
            .into_connection();
        let result = register::select_data(uid, &db).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.uid, expected_model.uid);
        assert_eq!(result.hashed_key, expected_model.hashed_key);
        assert_eq!(result.salt, expected_model.salt);
    }

    #[tokio::test]
    async fn test_select_data_not_found() {
        let uid = "non_existent_uid";
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![Vec::<register::Model>::new()])
            .into_connection();
        let result = register::select_data(uid, &db).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RegisterError::RecordNotFound(msg) => assert!(msg.contains(uid)),
            _ => panic!("Expected RecordNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_insert_data_success() {
        let mut info = ApiKeyInfo {
            uid: "new_uid".to_string(),
            hashed_key: b"hashed_key".to_vec(),
            salt: b"salt".to_vec(),
            apikey: "".to_string(),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();
        let result = register::insert_data(&mut info, &db).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insert_data_failure() {
        let mut info = ApiKeyInfo {
            uid: "new_uid".to_string(),
            hashed_key: b"hashed_key".to_vec(),
            salt: b"salt".to_vec(),
            apikey: "".to_string(),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_errors(vec![DbErr::RecordNotInserted])
            .into_connection();
        let result = register::insert_data(&mut info, &db).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RegisterError::DbError(msg) => assert!(msg.contains("insert data error")),
            _ => panic!("Expected DbError"),
        }
    }

    #[tokio::test]
    async fn test_update_data_success() {
        let mut info = ApiKeyInfo {
            uid: "existing_uid".to_string(),
            hashed_key: b"new_hashed_key".to_vec(),
            salt: b"new_salt".to_vec(),
            apikey: "".to_string(),
        };
        let original_model = register::Model {
            uid: info.uid.clone(),
            hashed_key: "old_hashed_key".to_string(),
            salt: "old_salt".to_string(),
        };
        let expected_updated = register::Model {
            uid: info.uid.clone(),
            hashed_key: general_purpose::STANDARD.encode(&info.hashed_key),
            salt: general_purpose::STANDARD.encode(&info.salt),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![original_model]])
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .append_query_results(vec![vec![expected_updated.clone()]])
            .into_connection();
        let result = register::update_data(&mut info, &db).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_data_not_found() {
        let mut info = ApiKeyInfo {
            uid: "non_existent_uid".to_string(),
            hashed_key: b"new_hashed_key".to_vec(),
            salt: b"new_salt".to_vec(),
            apikey: "".to_string(),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![Vec::<register::Model>::new()])
            .into_connection();
        let result = register::update_data(&mut info, &db).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RegisterError::RecordNotFound(msg) => assert!(msg.contains(&info.uid)),
            _ => panic!("Expected RecordNotFound error"),
        }
    }
}