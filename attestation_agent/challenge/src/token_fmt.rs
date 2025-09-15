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

use config::config::{VALID_TOKEN_FORMATS};

/// None is considered valid (means default will be used). Empty string is invalid.
pub fn is_valid(opt_fmt: &Option<String>) -> bool {
    match opt_fmt {
        None => true,
        Some(s) => {
            if s.is_empty() {
                return false;
            }
            VALID_TOKEN_FORMATS.iter().any(|&v| s.eq_ignore_ascii_case(v))
        }
    }
}