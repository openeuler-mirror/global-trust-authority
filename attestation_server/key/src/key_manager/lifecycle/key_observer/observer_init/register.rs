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

use crate::key_manager::lifecycle::key_observer::KeyLifecycleObserver;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use std::sync::Mutex;

pub static OBSERVER_REGISTRY: OnceCell<Mutex<Vec<Arc<dyn KeyLifecycleObserver + Send + Sync>>>> =
    OnceCell::new();

pub fn register_observer(observer: Arc<dyn KeyLifecycleObserver + Send + Sync>) {
    let registry = OBSERVER_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    registry.lock().unwrap().push(observer);
}

// mod tests {
//     #![allow(warnings)]
//     use super::*;
//     use std::fmt::{Debug, Formatter};
//     use std::future::Future;
//     use crate::key_manager::lifecycle::key_observer::key_lifecycle_observer::BoxFuture;
//     use sea_orm::DatabaseTransaction;
//     use crate::key_manager::error::KeyManagerError;
//     use crate::key_manager::lifecycle::KeyLifecycleObserver;
// 
//     struct MockKeyLifecycleObserver {}
// 
//     impl Debug for MockKeyLifecycleObserver {
//         fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
//             Ok(())
//         }
//     }
// 
//     impl KeyLifecycleObserver for MockKeyLifecycleObserver {
//         fn signature_update(&self, key_version: & str, tx: Arc<&DatabaseTransaction>) -> BoxFuture<Result<(), Box<KeyManagerError>>> {
//             Box::pin(async move {
//                 Ok(())
//             })
//         }
//     }
//     
//     #[test]
//     fn test_register_observer() {
//         let observer = Arc::new(MockKeyLifecycleObserver{});
//         register_observer(observer);
//         assert!(OBSERVER_REGISTRY.get().is_some())
//     }
// }