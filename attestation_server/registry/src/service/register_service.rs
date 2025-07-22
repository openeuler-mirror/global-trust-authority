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
    use std::sync::Arc;
    use actix_web::web;
    use crate::apikey::register::{generate_apikey, get_hashed_key, refresh_apikey, ApiKeyInfo};
    use crate::error::register_error::RegisterError;
    use crate::repository::register_repository::register::{insert_data, select_data, update_data};
    use base64::engine::general_purpose;
    use base64::Engine;
    use sea_orm::DatabaseConnection;
    use subtle::ConstantTimeEq;
    use zeroize::Zeroize;
    use common_log::{debug, error};

    pub async fn register_apikey(db: web::Data<Arc<DatabaseConnection>>) -> Result<ApiKeyInfo, RegisterError> {
        debug!("start registry api key");
        let mut info = generate_apikey()?;
        insert_data(&mut info, &db).await?;
        debug!("registry api key success {:?}", &info.uid);
        Ok(info)
    }

    pub async fn update_apikey(apikey_info: &mut ApiKeyInfo, db: web::Data<Arc<DatabaseConnection>>) -> Result<(), RegisterError> {
        debug!("start select api key {:?}", &apikey_info.uid);
        let info = select_data(apikey_info.uid.as_str(), &db).await;
        let data = match info {
            Ok(data) => {
                debug!("select success {:?}", &apikey_info.uid);
                data
            },
            Err(err) => {
                error!("select data error {:?}", err);
                return Err(err);
            }
        };
        data.hashed_key.into_bytes().zeroize();
        let salt = general_purpose::STANDARD.decode(data.salt.as_str());
        data.salt.into_bytes().zeroize();
        apikey_info.salt = salt.map_err(|err| {
            error!("decode salt error {:?}", err);
            RegisterError::Base64DecodeFound("decode salt error".to_string())
        })?;
        refresh_apikey(apikey_info).map_err(|err| {
            apikey_info.salt.zeroize();
            err
        })?;
        apikey_info.salt.zeroize();
        update_data(apikey_info, &db).await?;
        debug!("update success {:?}", &apikey_info.uid);
        Ok(())
    }

    pub async fn check_apikey(apikey_info: &ApiKeyInfo, db: web::Data<Arc<DatabaseConnection>>) -> Result<bool, RegisterError> {
        let info = select_data(apikey_info.uid.as_str(), &db).await;
        let data = match info {
            Ok(data) => {
                debug!("select success {:?}", &apikey_info.uid);
                data
            }
            Err(err) => {
                error!("uid is not in database, {:?}", err);
                return Ok(false);
            }
        };
        let salt = general_purpose::STANDARD.decode(data.salt.as_str());
        data.salt.into_bytes().zeroize();
        let salt = match salt {
            Ok(salt) => salt,
            Err(err) => {
                data.hashed_key.into_bytes().zeroize();
                error!("decode salt error {:?}", err);
                return Err(RegisterError::Base64DecodeFound("decode salt error".to_string()))
            }
        };
        let hashed_key = get_hashed_key(&apikey_info.apikey, &salt);
        let hashed_key = match hashed_key {
            Ok(hashed_key) => hashed_key,
            Err(err) => {
                data.hashed_key.into_bytes().zeroize();
                return Err(err);
            }
        };
        let hashed_key = general_purpose::STANDARD.encode(hashed_key);
        let result = hashed_key.as_bytes().ct_eq(data.hashed_key.as_bytes()).into();
        hashed_key.into_bytes().zeroize();
        data.hashed_key.into_bytes().zeroize();
        Ok(result)
    }


}

#[cfg(test)]
mod tests {
    use actix_web::web;
    use std::sync::Arc;
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
    use crate::apikey::register::ApiKeyInfo;
    use crate::error::register_error::RegisterError;
    use crate::service::register_service::register::{check_apikey, register_apikey, update_apikey};

    async fn setup_test_db() -> Result<web::Data<Arc<DatabaseConnection>>, RegisterError> {
        let db = Database::connect("sqlite::memory:?mode=memory&cache=shared").await
            .map_err(|e| RegisterError::DbError(e.to_string()))?;
        db.execute(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "
        CREATE TABLE IF NOT EXISTS t_apikey_info (
            uid TEXT NOT NULL,
            hashed_key TEXT NOT NULL,
            salt TEXT NOT NULL    
        );
    ".to_string())).await.map_err(|e| RegisterError::DbError(e.to_string()))?;
        db.execute(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "
        CREATE TABLE IF NOT EXISTS dual (dummy INTEGER);
        INSERT OR IGNORE INTO dual VALUES (1);
    ".to_string())).await.map_err(|e| RegisterError::DbError(e.to_string()))?;
        Ok(web::Data::new(Arc::new(db)))
    }

    #[tokio::test]
    async fn test_register_apikey_success() {
        let db = setup_test_db().await.unwrap();
        let result = register_apikey(db).await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(!info.uid.is_empty());
        assert!(info.hashed_key.is_empty());
        assert!(info.salt.is_empty());
    }
    
    #[tokio::test]
    async fn test_update_apikey_success() {
        let db = setup_test_db().await.unwrap();
        let result = register_apikey(db.clone()).await;
        assert!(result.is_ok());
        let mut info = result.unwrap();
        let result1 = update_apikey(&mut info, db).await;
        assert!(result1.is_ok());
    }
    
    #[tokio::test]
    async fn test_check_apikey_valid() {
        let db = setup_test_db().await.unwrap();
        let result = register_apikey(db.clone()).await;
        assert!(result.is_ok());
        let info = result.unwrap();
        let result = check_apikey(&info, db).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[tokio::test]
    async fn test_check_apikey_invalid() {
        let db = setup_test_db().await.unwrap();
        let info = ApiKeyInfo {
            uid: "new_uid".to_string(),
            hashed_key: b"hashed_key".to_vec(),
            salt: b"salt".to_vec(),
            apikey: "".to_string(),
        };
        let result = check_apikey(&info, db).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}