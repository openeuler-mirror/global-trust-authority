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

use std::sync::Arc;
use lazy_static::lazy_static;
use redis::Client;
use std::sync::Mutex;
use crate::error::RedisError;

lazy_static! {
    static ref REDIS_CLIENT: Arc<Mutex<Option<RedisClient>>> = Arc::new(Mutex::new(None));
}

#[derive(Clone, Debug)]
pub struct RedisClient {
    pub(crate) client: Client,
}

impl RedisClient {
    ///Get the RedisClient instance and automatically initialize it if the instance does not exist
    ///
    ///This method reads the Redis connection address from environment variables REDIS_URL
    ///If the instance does not exist, a new instance will be automatically created and saved to the global static variable
    pub fn get_instance() -> Result<RedisClient, RedisError> {
        let mut global_client = REDIS_CLIENT.lock().map_err(|_| 
            RedisError::OperationError("Failed to acquire lock".to_string()))?;
        
        if global_client.is_none() {
            let redis_url = std::env::var("REDIS_URL")
                .map_err(|_| RedisError::OperationError("REDIS_URL environment variable not set".to_string()))?;
            
            let client = Client::open(&*redis_url)
                .map_err(RedisError::ConnectionError)?;

            let redis_client = RedisClient {
                client,
            };

            *global_client = Some(redis_client);
        }

        global_client
            .as_ref()
            .cloned()
            .ok_or_else(|| RedisError::OperationError("Redis client initialization failed".to_string()))
    }
}