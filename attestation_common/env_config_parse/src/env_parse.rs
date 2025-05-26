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

use std::env;
use log::{error, info};

pub async fn get_pod_name() -> String {
    get_env_value("POD_NAME").await
}

pub async fn get_env_value(key: &str) -> String {
    info!("will be get values for key {}", key);
    match env::var(key) {
        Ok(value) => value.to_string(),
        Err(e) => {
            error!("Failed to get environment variable {}: {:?}", key, e);
            String::new() // Returns a default value, such as an empty string.
        }
    }
}