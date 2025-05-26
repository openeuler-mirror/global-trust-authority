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


use thiserror::Error;

#[derive(Debug, Error)]
pub enum DistributedLockError {
    #[error("Redis operation failed: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("Lock acquisition timeout")]
    AcquireTimeout,

    #[error("Lock does not exist or has expired")]
    LockNotExists,

    #[error("No permission to operate this lock")]
    InvalidLockOwner,

    #[error("Parameter error: {0}")]
    InvalidArgument(String),
}

pub type Result<T> = std::result::Result<T, DistributedLockError>;