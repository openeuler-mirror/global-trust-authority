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

use std::ops::{Deref, DerefMut};
use std::time::Duration;
use redis::Commands;
use crate::client::RedisClient;
use crate::error::RedisError;

impl RedisClient {
    /// Sets the value for a given key in Redis.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to set.
    /// * `value` - The value to store.
    /// * `ttl` - An optional duration for the key's expiration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or a `RedisError` on failure.
    /// 
    /// # Errors
    /// * `RedisError::ConnectionError` - If there is an error connecting to Redis.
    pub fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        if let Some(ttl) = ttl {
            conn.set_ex(key, value, ttl.as_secs() as usize)
                .map_err(RedisError::ConnectionError)?
        } else {
            conn.set(key, value)
                .map_err(RedisError::ConnectionError)?
        }

        Ok(())
    }

    /// Gets the value for a given key from Redis.
    ///
    /// # Arguments
    ///
    /// * `key` - The key whose value is to be retrieved.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the value on success, `RedisError::KeyNotFound`
    /// if the key does not exist, or `RedisError::ConnectionError` on other failures.
    /// 
    /// # Errors
    /// * `RedisError::KeyNotFound` - If the key does not exist.
    pub fn get(&self, key: &str) -> Result<String, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        let value: String = conn.get(key)
            .map_err(|e| match e.kind() {
                redis::ErrorKind::TypeError => RedisError::KeyNotFound,
                _ => RedisError::ConnectionError(e)
            })?;
        Ok(value)
    }

    /// Deletes a key from Redis.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to delete.
    /// 
    /// # Returns
    /// 
    /// Returns `Ok(())` on success, or `RedisError` on failure.
    /// 
    ///  #Errors
    ///  * `RedisError::KeyNotFound` - If the key does not exist.
    pub fn del(&self, key: &str) -> Result<(), RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.del(key)
            .map_err(RedisError::ConnectionError)
    }

    /// Checks if a key exists in Redis.
    /// 
    /// #Arguments
    /// 
    /// * `key` - The key to check.
    /// 
    /// #Returns
    /// 
    /// Returns `Ok(bool)` indicating whether the key exists, or `RedisError` on failure.
    /// 
    /// #Errors
    /// * `RedisError::KeyNotFound` - If the key does not exist.
    pub fn exists(&self, key: &str) -> Result<bool, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.exists(key)
            .map_err(RedisError::ConnectionError)
    }

    /// Sets the expiration time for a key in Redis.
    ///
    /// # Arguments
    /// 
    /// * `key` - The key to set the expiration for.
    /// * `ttl` - The expiration time in seconds.
    /// 
    /// # Returns
    ///     
    /// Returns `Ok(bool)` indicating whether the expiration was set successfully,
    /// 
    /// # Errors
    /// 
    /// * `RedisError::KeyNotFound` - If the key does not exist.
    pub fn expire(&self, key: &str, ttl: Duration) -> Result<bool, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.expire(key, ttl.as_secs() as usize)
            .map_err(RedisError::ConnectionError)
    }

    /// Gets the remaining time to live for a key in Redis.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to get the TTL for.
    /// 
    /// # Returns
    /// 
    /// Returns `Ok(i64)` containing the remaining TTL in seconds, or `RedisError` on failure.
    /// 
    /// # Errors
    ///     
    /// * `RedisError::KeyNotFound` - If the key does not exist.
    pub fn ttl(&self, key: &str) -> Result<i64, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.ttl(key)
            .map_err(RedisError::ConnectionError)
    }

    /// Sets a key in Redis if it does not already exist.
    ///
    /// # Arguments
    /// 
    /// * `key` - The key to set.
    /// * `value` - The value to store.
    /// * `ttl` - An optional duration for the key's expiration.
    /// 
    /// # Returns
    /// 
    /// Returns `Ok(bool)` indicating whether the key was set successfully,
    /// 
    /// # Errors
    /// 
    /// * `RedisError::KeyNotFound` - If the key does not exist. 
    pub fn set_nx(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<bool, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        let result = conn.set_nx(key, value)
            .map_err(RedisError::ConnectionError)?;
        
        if result && ttl.is_some() {
            conn.expire::<_, ()>(key, ttl.unwrap().as_secs() as usize)?;
        }
        
        Ok(result)
    }
}

impl Deref for RedisClient {
    type Target = redis::Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for RedisClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}