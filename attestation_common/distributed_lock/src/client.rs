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

use std::time::Duration;
use cache::client::RedisClient;
use super::error::Result;
use super::scripts::{RELEASE_LOCK, EXTEND_LOCK};

/// Redis client side encapsulation, providing distributed lock related operations
#[derive(Debug)]
pub struct LockRedisClient {
    client: RedisClient,
}

impl LockRedisClient {
    /// Create a RedisClient instance
    pub fn new() -> Result<Self> {
        let client = RedisClient::get_instance().unwrap();
        Ok(Self { client })
    }

    /// Acquire lock
    pub fn acquire_lock(&self, key: &str, value: &str, ttl: u64, timeout: u64) -> Result<bool> {
        let conn = self.client.clone();
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout);

        while start.elapsed() < timeout {
            let result: bool = conn.set_nx(key, value, None).unwrap();
            if result {
                conn.expire(key, Duration::from_secs(ttl)).unwrap();
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(false)
    }

    /// Release lock
    pub fn release_lock(&self, key: &str, value: &str) -> Result<bool> {
        let mut conn = self.client.clone();
        let result: i32 = redis::Script::new(RELEASE_LOCK)
            .key(key)
            .arg(value)
            .invoke(&mut conn)?;
        Ok(result == 1)
    }

    /// Acquire the expiration time of the lock
    pub fn get_lock_ttl(&self, key: &str) -> Result<Option<u64>> {
        let conn = self.client.clone();
        let ttl = conn.ttl(key).unwrap();
        if ttl > 0 {
            Ok(Some(ttl as u64))
        } else {
            Ok(None)
        }
    }

    /// Extend the expiration time of the lock
    pub fn extend_lock_ttl(&self, key: &str, value: &str, ttl: u64) -> Result<bool> {
        let mut conn = self.client.clone();
        let result: i32 = redis::Script::new(EXTEND_LOCK)
            .key(key)
            .arg(value)
            .arg(ttl)
            .invoke(&mut conn)?;
        Ok(result == 1)
    }
}