use std::env;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

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