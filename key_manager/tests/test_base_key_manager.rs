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

#[cfg(test)]
mod tests {
    use key_managerd::key_manager::base_key_manager::{PrivateKey};

    #[test]
    fn test_private_key_default() {
        let key = PrivateKey::default();
        assert!(key.version.is_empty());
        assert!(key.private_key.is_empty());
        assert!(key.algorithm.is_empty());
        assert!(key.encoding.is_empty());
    }

    #[test]
    fn test_private_key_new() {
        let key = PrivateKey::new("v1".to_string(), "test_key".to_string(), "RSA".to_string(), "PEM".to_string());
        assert_eq!(key.version, "v1");
        assert_eq!(key.private_key, "test_key");
        assert_eq!(key.algorithm, "RSA");
        assert_eq!(key.encoding, "PEM");
    }
}