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
    use rdb::get_connection;
    use sea_orm::{entity::prelude::*, ActiveValue::Set};
    use serde::Serialize;
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

    pub async fn select_data(uid: &str) -> Result<Model, RegisterError> {
        let connect = get_connection().await?;
        let connection = connect.as_ref();
        let key = Entity::find_by_id(uid.to_string())
            .one(connection)
            .await?
            .ok_or(RegisterError::RecordNotFound(format!("uid: {}", uid)))?;
        Ok(key)
    }

    pub async fn update_date(info: &register::ApiKeyInfo) -> Result<Model, RegisterError> {
        let connect = get_connection().await?;
        let connection = connect.as_ref();

        let model = Entity::find_by_id(info.uid.to_string())
            .one(connection)
            .await?
            .ok_or(RegisterError::RecordNotFound(format!("uid: {}", info.uid)))?;

        let mut active_model: ActiveModel = model.into();
        active_model.hashed_key = Set(general_purpose::STANDARD.encode(&info.hashed_key));
        active_model.salt = Set(general_purpose::STANDARD.encode(&info.salt));
        let update = active_model.update(connection).await?;
        Ok(update)
    }

    pub async fn insert_data(info: &register::ApiKeyInfo) -> Result<(), RegisterError> {
        let connect = get_connection().await?;
        let connection = connect.as_ref();

        let active_model = ActiveModel {
            uid: Set(info.uid.to_string()),
            hashed_key: Set(general_purpose::STANDARD.encode(&info.hashed_key)),
            salt: Set(general_purpose::STANDARD.encode(&info.salt)),
            ..Default::default()
        };

        match Entity::insert(active_model).exec(connection).await {
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
