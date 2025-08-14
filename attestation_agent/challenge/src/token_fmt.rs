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

use config::config::{VALID_TOKEN_FORMATS, DEFAULT_TOKEN_FORMAT};

/// Sanitize an Option<String> token_fmt: lowercase, empty -> None
pub fn sanitize(token_fmt: Option<String>) -> Option<String> {
    token_fmt.and_then(|fmt| {
        if fmt.is_empty() { None } else { Some(fmt.to_lowercase()) }
    })
}

/// None or empty is considered valid (means default will be used).
pub fn is_valid(opt_fmt: &Option<String>) -> bool {
    match opt_fmt.as_deref().filter(|s| !s.is_empty()) {
        Some(fmt) => VALID_TOKEN_FORMATS.iter().any(|&v| fmt.eq_ignore_ascii_case(v)),
        None => true,
    }
}

/// Return normalized token_fmt string or default "eat" when None
pub fn normalized_or_default(opt_fmt: &Option<String>) -> String {
    sanitize(opt_fmt.clone()).unwrap_or_else(|| DEFAULT_TOKEN_FORMAT.to_string())
}