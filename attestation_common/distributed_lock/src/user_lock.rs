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

use std::thread;
use std::time::Duration;

use log::{error, info};

use super::{DistributedLockError, Lock};

pub struct UserLock {
    lock: Lock,
}

impl UserLock {
    pub fn new(key: String, value: String, ttl: u64, timeout: u64) -> Self {
        Self {
            lock: Lock::new(&key, &value, ttl, timeout).unwrap(),
        }
    }

    pub fn acquire(&self) -> Result<(), DistributedLockError> {
        let mut retries = 0;
        while retries < 3 {
            match self.lock.acquire() {
                Ok(true) => {
                    info!("Acquired lock");
                    return Ok(());
                }
                Ok(false) => {
                    info!(
                        "Failed to acquire lock, retrying... (attempt {}/{})",
                        retries + 1,
                        3
                    );
                    thread::sleep(Duration::from_secs(10));
                    retries += 1;
                }
                Err(e) => {
                    error!("Failed to acquire lock: {}", e);
                    return Err(DistributedLockError::AcquireTimeout);
                }
            }
        }
        Err(DistributedLockError::AcquireTimeout)
    }
}

impl Drop for UserLock {
    fn drop(&mut self) {
        if let Err(e) = self.lock.release() {
            error!("Failed to release lock: {}", e);
        }
    }
}