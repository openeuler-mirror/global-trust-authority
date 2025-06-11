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

use std::env;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Recursively searches for a file with the given name starting from the current directory.
///
/// # Arguments
///
/// * `file_name` - The name of the file to search for.
///
/// # Returns
///
/// Returns `Ok(PathBuf)` containing the canonicalized absolute path of the found file,
/// or `Err(String)` if the file is not found or an error occurs during directory traversal
/// or path canonicalization.
pub fn find_file(file_name: &str) -> Result<PathBuf, String> {
    // Get the absolute path of the current running directory
    let current_dir = env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?;

    // Normalize paths (handle '.' and '.. `）
    let current_dir = current_dir.canonicalize()
        .map_err(|e| format!("Failed to canonicalize path: {}", e))?;
    // Recursively traverses the current directory
    for entry in WalkDir::new(&current_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.file_name() == Some(Path::new(file_name).as_os_str()) {
            // Return to the absolute path
            return path.canonicalize()
                .map_err(|e| format!("Failed to canonicalize file path: {}", e));
        }
    }

    Err(format!("File '{}' not found in {}", file_name, current_dir.display()))
}
