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

/// service version
pub const SERVICE_VERSION: &str = "1.0";

/// config file name
pub const YAML_CONFIG_FILE_PATH: &str = "server_config.yaml";

/// nonce period
pub const NONCE_PERIOD: &str = "attestation_service.nonce.nonce_valid_period";

/// valid types
pub const VALID_TYPES: &[&str] = &["ignore", "user", "default"];
