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

use serde::{Serialize, Deserialize};

// evidence structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    // No prefix and suffix, only the base64 content
    pub ak_cert: String,
    pub quote: Quote,
    pub pcrs: Pcrs,
    pub logs: Vec<Log>,
}

// quote structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Quote {
    pub quote_data: String,
    pub signature: String,
}

// pcrs structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Pcrs { 
    pub hash_alg: String,      // default value is sha256
    pub pcr_values: Vec<PcrValue>,
}

// pcr value structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PcrValue {
    pub pcr_index: i32,
    pub pcr_value: String,
}

// log structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub log_type: String,       // example value: TcgEventLog, ImaLog
    pub log_data: String,
}

