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

use std::collections::HashMap;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};


pub async fn get_config_value(filename: &str, key: &str) -> Result<Option<String>, String> {
    let file_maps = parse_file(filename).await?;
    let value = file_maps.get(key).cloned();
    Ok(value)
}

pub async fn get_config_values(filename: &str) -> Result<HashMap<String, String>, String> {
    let file_maps = parse_file(filename).await?;
    Ok(file_maps)
}

async fn parse_file(file_path: &str) -> Result<HashMap<String, String>, String> {
    // Try to open file
    let file = File::open(file_path).await.map_err(|e| format!("Failed to open file: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut config_map = HashMap::new();
    
    // Read file content line by line - modified to async reading
    let mut line = String::new();
    while let Ok(bytes_read) = reader.read_line(&mut line).await {
        if bytes_read == 0 {
            break; // End of file
        }
        
        if let Some((key, value)) = parse_line(&line) {
            config_map.insert(key, value);
        }
        
        line.clear(); // Clear string for next read
    }
    
    Ok(config_map)
}

// Assume each line in config file has format key=value
fn parse_line(line: &str) -> Option<(String, String)> {
    if let Some((key, value)) = line.split_once('=') {
        Some((key.trim().to_string(), value.trim().to_string()))
    } else {
        None
    }
}