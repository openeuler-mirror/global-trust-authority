use std::fs::File;
use std::io::Read;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Read a file and convert it to a Base64 encoded string
///
/// # Parameters
/// * `path` - File path
///
/// # Returns
/// * `Result<String, std::io::Error>` - Base64 encoded string on success, IO error on failure
pub fn read_file_as_base64(path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(BASE64.encode(buffer))
}

/// Create corrupted Base64 data for testing
///
/// # Parameters
/// * `data` - Original Base64 string
///
/// # Returns
/// * `String` - Corrupted Base64 string
pub fn corrupt_base64_data(data: &str) -> String {
    let mut corrupted = data.to_string();
    if corrupted.len() > 100 {
        // Insert corrupted content in the middle section
        let mid = corrupted.len() / 2;
        corrupted.replace_range(mid..mid+10, "CORRUPTED!!");
    }
    corrupted
}
