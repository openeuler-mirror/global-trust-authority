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
    use crate::apikey::register::{generate_apikey, get_hashed_key, refresh_apikey, ApiKeyInfo};
    use crate::error::register_error::RegisterError;
    use crate::repository::register_repository::register::{insert_data, select_data, update_date};
    use base64::engine::general_purpose;
    use base64::Engine;
    use common_log::{debug, error};

    pub async fn register_apikey() -> Result<ApiKeyInfo, RegisterError> {
        debug!("start register api key");
        let info = generate_apikey()?;
        insert_data(&info).await?;
        debug!("register api key success {:?}", &info.uid);
        Ok(info)
    }

    pub async fn update_apikey(apikey_info: &mut ApiKeyInfo) -> Result<(), RegisterError> {
        debug!("start select api key {:?}", &apikey_info.uid);
        let info = select_data(apikey_info.uid.as_str()).await;
        match info {
            Ok(_) => debug!("select success {:?}", &apikey_info.uid),
            Err(err) => {
                error!("select data error {:?}", err);
                return Err(err);
            }
        };
        refresh_apikey(apikey_info)?;
        update_date(&apikey_info).await?;
        debug!("update success {:?}", &apikey_info.uid);
        Ok(())
    }

    pub async fn check_apikey(apikey_info: &ApiKeyInfo) -> Result<bool, RegisterError> {
        let info = select_data(apikey_info.uid.as_str()).await;
        let data = match info {
            Ok(data) => {
                debug!("select success {:?}", &apikey_info.uid);
                data
            }
            Err(err) => {
                error!("select data error {:?}", err);
                return Err(err);
            }
        };
        let salt = match general_purpose::STANDARD.decode(data.salt.as_str()) {
            Ok(salt) => salt,
            Err(err) => {
                error!("decode salt error {:?}", err);
                return Err(RegisterError::DatabaseError("".to_string()));
            }
        };
        let hashed_key = get_hashed_key(&apikey_info.apikey, &salt)?;
        let hashed_key = general_purpose::STANDARD.encode(hashed_key);
        Ok(hashed_key == data.hashed_key)
    }


}