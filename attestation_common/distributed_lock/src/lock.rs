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

use super::client::LockRedisClient;
use super::error::Result;

/// Distributed Lock Structure
#[derive(Debug)]
pub struct Lock {
    /// Lock key name
    key: String,
    /// Lock value, used to identify the lock owner
    value: String,
    /// Lock expiration time (seconds)
    ttl: u64,
    /// Lock acquisition timeout (seconds)
    timeout: u64,
    /// Redis client
    client: LockRedisClient,
}

impl Lock {
    /// Create a new distributed lock instance
    pub fn new(key: impl Into<String>, value: impl Into<String>, ttl: u64, timeout: u64) -> Result<Self> {
        Ok(Self {
            key: key.into(),
            value: value.into(),
            ttl,
            timeout,
            client: LockRedisClient::new()?,
        })
    }

    /// Acquire the lock
    pub fn acquire(&self) -> Result<bool> {
        self.client.acquire_lock(&self.key, &self.value, self.ttl, self.timeout)
    }

    /// Release the lock
    pub fn release(&self) -> Result<bool> {
        self.client.release_lock(&self.key, &self.value)
    }

    /// Get lock expiration time
    pub fn get_ttl(&self) -> Result<Option<u64>> {
        self.client.get_lock_ttl(&self.key)
    }

    /// Extend the lock's expiration time
    pub fn extend_ttl(&self, ttl: u64) -> Result<bool> {
        self.client.extend_lock_ttl(&self.key, &self.value, ttl)
    }

    /// Get lock key name
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Get lock value
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Get lock expiration time setting
    pub fn ttl(&self) -> u64 {
        self.ttl
    }

    /// Get lock acquisition timeout setting
    pub fn timeout(&self) -> u64 {
        self.timeout
    }
}