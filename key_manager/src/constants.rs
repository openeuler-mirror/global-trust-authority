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

// 编码类型 pem
pub const ENCODING_PEM: &str = "pem";

// 算法类型
pub const ALGORITHM_RSA_3072: &str = "rsa_3072";
pub const ALGORITHM_RSA_4096: &str = "rsa_4096";
pub const ALGORITHM_EC: &str = "ec";
pub const ALGORITHM_SM2: &str = "sm2";

pub const RSA_3072_KEY_SIZE: u32 = 3072;
pub const RSA_4096_KEY_SIZE: u32 = 4096;

pub const MAX_PRIVATE_KEY_SIZE: u64 = 10 * 1024 * 1024; // 10MB