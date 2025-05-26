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

use once_cell::sync::OnceCell;
use openssl::pkey::{PKey, Private, Public};
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub cached_private: OnceCell<PKey<Private>>,
    pub cached_public: OnceCell<PKey<Public>>,

    pub private_bytes: Vec<u8>,
    pub public_bytes: Vec<u8>,

    pub algorithm: String,
}

impl KeyPair {
    /// The thread safely obtains the private key
    pub fn private_key(&self) -> &PKey<Private> {
        self.cached_private.get_or_init(|| {
            PKey::private_key_from_pem(&self.private_bytes).expect("Invalid private key PEM")
        })
    }

    /// The thread safely obtains the public key
    pub fn public_key(&self) -> &PKey<Public> {
        self.cached_public.get_or_init(|| {
            PKey::public_key_from_pem(&self.public_bytes).expect("Invalid public key PEM")
        })
    }
}

impl Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair(private_bytes: {}, public_bytes: {})",
            self.private_bytes.len(),
            self.public_bytes.len()
        )
    }
}

#[allow(warnings)]
mod tests {

    use super::*;
    use openssl::rsa::Rsa;

    #[test]
    fn test_key_pair() {
        let private_bytes = Rsa::generate(2048).unwrap().private_key_to_pem().unwrap();
        let public_bytes = PKey::private_key_from_pem(&private_bytes).unwrap().public_key_to_pem().unwrap();
        let key_pair = KeyPair {
            cached_private: OnceCell::new(),
            cached_public: OnceCell::new(),
            private_bytes: private_bytes.clone(),
            public_bytes,
            algorithm: "rsa".to_string(),
        };
        let private_key = key_pair.private_key();
        assert_eq!(private_key.size(), 256);
        let public_key = key_pair.public_key();
        assert_eq!(public_key.size(), 256);
    }
}

