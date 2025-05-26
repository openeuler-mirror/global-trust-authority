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

pub mod config {
    pub const SECRET_PATH: &'static str = "key_manager";
    pub const TOKEN_ARRAY: [&'static str; 3] = ["FSK", "NSK", "TSK"];
    pub const KEY_MANAGER_PORT: &'static str = "KEY_MANAGER_PORT";
    pub const KEY_MANAGER_CERT_PATH: &'static str = "KEY_MANAGER_CERT_FILE_PATH";
    pub const KEY_MANAGER_KEY_PATH: &'static str = "KEY_MANAGER_KEY_FILE_PATH";
    pub const ROOT_CA_CERT_PATH: &'static str = "ROOT_CA_CERT_PATH";
    pub const KEY_MANAGER_LOG_LEVEL: &'static str = "KEY_MANAGER_LOG_LEVEL";
    pub const KEY_MANAGER_LOG_PATH: &'static str = "KEY_MANAGER_LOG_PATH";
    pub const KEY_MANAGER_ROOT_TOKEN: &'static str = "KEY_MANAGER_ROOT_TOKEN";
    pub const KEY_MANAGER_SECRET_ADDR: &'static str = "KEY_MANAGER_SECRET_ADDR";
    pub const OPENBAO_TOKEN_ENV_KEY: &'static str = "BAO_TOKEN";
    pub const OPENBAO_ADDR_ENV_KEY: &'static str = "BAO_ADDR";
}