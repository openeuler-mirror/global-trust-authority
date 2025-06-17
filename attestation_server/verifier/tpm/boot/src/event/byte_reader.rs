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

//! Byte Reader Module
//!
//! This module provides tools for parsing binary data from byte streams.
//! Primarily used for TPM event log parsing, it offers a series of convenient methods
//! for reading different types of data, including basic types (such as u8, u16, u32, u64),
//! strings, GUIDs, and Unicode strings.
//!
//! The module contains two main components:
//! - `ByteReader`: A byte stream reader providing methods for reading various data types
//! - `ByteParseable`: A parseable trait; types implementing this trait can be parsed directly from byte streams

use byteorder::{LittleEndian, ReadBytesExt};
use plugin_manager::PluginError;
use std::io::{Cursor, Read};
use uuid::Uuid;

/// UEFI GUID size
pub const UEFI_GUID_SIZE: usize = 16;

/// Binary data parsing helper structure
///
/// Provides methods for reading various data types from byte streams, including basic types,
/// strings, and complex structures. Internally uses Cursor for data reading and position tracking.
pub struct ByteReader<'a> {
    cursor: Cursor<&'a [u8]>,
}

/// Trait for types that can be parsed from a byte stream
///
/// Types implementing this trait can be directly parsed from a ByteReader.
/// This trait is primarily used for handling binary data formats, such as structures in TPM event logs.
///
/// # Example
///
/// ```rust ignore
/// use tpm_boot_verifier::byte_reader::{ByteReader, ByteParseable};
/// use plugin_manager::PluginError;
///
/// struct MyStruct {
///     field1: u32,
///     field2: String,
/// }
///
/// impl ByteParseable for MyStruct {
///     fn parse_from(parser: &mut ByteReader) -> Result<Self, PluginError> {
///         let field1 = parser.read_u32()?;
///         let field2 = parser.read_string(16)?;
///         Ok(Self { field1, field2 })
///     }
/// }
/// ```
pub trait ByteParseable: Sized {
    /// Parse an instance of the current type from a byte reader
    ///
    /// # Parameters
    ///
    /// * `parser` - A ByteReader instance used for reading and parsing bytes
    ///
    /// # Returns
    ///
    /// * `Result<Self, PluginError>` - Returns the parsed instance on success, or an error on failure
    ///
    /// # Errors
    ///
    /// Returns a PluginError when the byte stream contains insufficient data or is incorrectly formatted
    fn parse_from(parser: &mut ByteReader<'_>) -> Result<Self, PluginError>;
}

impl<'a> ByteReader<'a> {
    /// Create a new parser
    ///
    /// # Parameters
    /// * `data` - The byte data to be parsed
    ///
    /// # Returns
    /// * `Self` - The newly created ByteReader instance
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }
    
    /// Get the current position
    ///
    /// # Returns
    /// * `u64` - Current reading position (byte offset)
    pub fn position(&self) -> u64 {
        self.cursor.position()
    }
    
    /// Set position
    ///
    /// # Parameters
    /// * `pos` - The position to set (byte offset)
    ///
    /// # Returns
    /// * `Result<(), PluginError>` - Returns empty on success, error on failure
    ///
    /// # Errors
    /// * Returns an error when the set position exceeds the data range
    pub fn set_position(&mut self, pos: u64) -> Result<(), PluginError> {
        if pos > self.cursor.get_ref().len() as u64 {
            return Err(PluginError::InputError("Position exceeds data range".to_string()));
        }
        self.cursor.set_position(pos);
        Ok(())
    }
    
    /// Get the number of unread bytes remaining
    ///
    /// # Returns
    /// * `u64` - Number of unread bytes remaining
    pub fn remaining(&self) -> u64 {
        let total: u64 = self.cursor.get_ref().len() as u64;
        let current: u64 = self.cursor.position();
        total.checked_sub(current).unwrap_or(0)
    }

    /// Read a u8 value
    ///
    /// # Returns
    /// * `Result<u8, PluginError>` - Returns the read u8 value on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains insufficient data
    pub fn read_u8(&mut self) -> Result<u8, PluginError> {
        self.cursor.read_u8()
            .map_err(|e| PluginError::InputError(format!("Failed to read u8: {}", e)))
    }
    
    /// Read a u16 value (little-endian)
    ///
    /// # Returns
    /// * `Result<u16, PluginError>` - Returns the read u16 value on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains insufficient data
    pub fn read_u16(&mut self) -> Result<u16, PluginError> {
        self.cursor.read_u16::<LittleEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to read u16: {}", e)))
    }
    
    /// Read a u32 value (little-endian)
    ///
    /// # Returns
    /// * `Result<u32, PluginError>` - Returns the read u32 value on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains insufficient data
    pub fn read_u32(&mut self) -> Result<u32, PluginError> {
        self.cursor.read_u32::<LittleEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to read u32: {}", e)))
    }
    
    /// Read a u64 value (little-endian)
    ///
    /// # Returns
    /// * `Result<u64, PluginError>` - Returns the read u64 value on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains insufficient data
    pub fn read_u64(&mut self) -> Result<u64, PluginError> {
        self.cursor.read_u64::<LittleEndian>()
            .map_err(|e| PluginError::InputError(format!("Failed to read u64: {}", e)))
    }
    
    /// Read bytes of specified length
    ///
    /// # Parameters
    /// * `length` - Number of bytes to read
    ///
    /// # Returns
    /// * `Result<Vec<u8>, PluginError>` - Returns the read byte array on success, error on failure
    ///
    /// # Errors
    /// * Returns an error when the requested number of bytes exceeds the remaining bytes
    pub fn read_bytes(&mut self, length: usize) -> Result<Vec<u8>, PluginError> {
        if length > self.remaining() as usize {
            return Err(PluginError::InputError(
                format!("Read exceeds data range: requested {} bytes but only {} bytes remain", 
                        length, self.remaining())
            ));
        }
        
        let mut buffer: Vec<u8> = vec![0u8; length];
        self.cursor.read_exact(&mut buffer)
            .map_err(|e| PluginError::InputError(format!("Failed to read bytes: {}", e)))?;
        Ok(buffer)
    }
    
    /// Read UTF-8 string
    ///
    /// # Parameters
    /// * `length` - Number of bytes to read
    ///
    /// # Returns
    /// * `Result<String, PluginError>` - Returns the read UTF-8 string on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains invalid UTF-8 data
    pub fn read_string(&mut self, length: usize) -> Result<String, PluginError> {
        let bytes: Vec<u8> = self.read_bytes(length)?;
        String::from_utf8(bytes)
            .map_err(|e| PluginError::InputError(format!("Failed to convert to UTF-8 string: {}", e)))
    }
    
    /// Read GUID (16 bytes)
    ///
    /// Reads 16 bytes of data and parses it into a standard GUID format string
    ///
    /// # Returns
    /// * `Result<String, PluginError>` - Returns the GUID string on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains invalid GUID data
    pub fn read_guid(&mut self) -> Result<String, PluginError> {
        // read guid
        let mut guid_bytes: [u8; UEFI_GUID_SIZE] = [0; UEFI_GUID_SIZE];
        self.cursor.read_exact(&mut guid_bytes)
            .map_err(|e| PluginError::InputError(format!("Failed to read guid: {}", e)))?;
        
        let guid: Uuid = Uuid::from_bytes_le(guid_bytes);
        Ok(guid.to_string())
    }

    /// Read Unicode name
    ///
    /// Reads Unicode characters (UTF-16LE) of the specified length, stopping when a null character is encountered
    ///
    /// # Parameters
    /// * `length` - Number of characters to read (2 bytes per character)
    ///
    /// # Returns
    /// * `Result<String, PluginError>` - Returns the Unicode string on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains invalid Unicode data
    pub fn read_unicode_name(&mut self, length: usize) -> Result<String, PluginError> {
        let mut unicode_name: String = String::new();
        for _ in 0..length as usize {
            let char_code = self.read_u16()?;
            if char_code == 0 {
                break;
            }   
            match std::char::from_u32(char_code as u32) {
                Some(c) => unicode_name.push(c),
                None => unicode_name.push('?'),
            }
        }
        Ok(unicode_name)
    }
    
    /// Read null-terminated string
    ///
    /// Reads characters from the current position until a null character is encountered or
    /// the maximum length is reached
    ///
    /// # Parameters
    /// * `max_length` - Maximum number of bytes to read
    ///
    /// # Returns
    /// * `Result<String, PluginError>` - Returns the UTF-8 string on success, error on failure
    ///
    /// # Errors
    /// * Returns an error when the byte stream contains invalid UTF-8 data or if a position overflow occurs
    pub fn read_null_terminated_string(&mut self, max_length: usize) -> Result<String, PluginError> {
        let start_pos: u64 = self.position();
        let mut end_pos: u64 = start_pos;
        
        // Find the position of NULL character
        while end_pos < self.cursor.get_ref().len() as u64 && end_pos - start_pos < max_length as u64 {
            if self.cursor.get_ref()[end_pos as usize] == 0 {
                break;
            }
            end_pos += 1;
        }
        
        // Save the result
        let result_bytes: &[u8] = &self.cursor.get_ref()[start_pos as usize..end_pos as usize];
        
        // Update position pointer, skip NULL character
        if end_pos < self.cursor.get_ref().len() as u64 && self.cursor.get_ref()[end_pos as usize] == 0 {
            self.cursor.set_position(end_pos + 1);  // +1 to skip NULL character
        } else {
            self.cursor.set_position(end_pos);
        }
        
        // Convert to string
        String::from_utf8(result_bytes.to_vec())
            .map_err(|e| PluginError::InputError(format!("Invalid UTF-8 sequence: {}", e)))
    }

    /// Read UCS-2 (UTF-16LE) string
    ///
    /// Reads a UCS-2 encoded string from the current position until the end of data or a null character is encountered
    /// UCS-2 is a subset of UTF-16, with each character represented by 2 bytes in little-endian order
    /// The string is terminated by a null character (2 bytes of 0)
    ///
    /// # Returns
    /// * `Result<String, PluginError>` - Returns the Unicode string on success, error on failure
    /// 
    /// # Errors
    /// * Returns an error when the byte stream contains invalid UCS-2 data
    pub fn read_ucs2_string(&mut self) -> Result<String, PluginError> {
        let mut unicode_str = String::new();

        // Process data in pairs of bytes (UCS-2 uses 2 bytes per character)
        while self.remaining() >= 2 {
            let code_unit = self.read_u16()?;

            // Break at NUL terminator
            if code_unit == 0 {
                break;
            }

            // Convert to char and append to string
            match std::char::from_u32(code_unit as u32) {
                Some(c) => unicode_str.push(c),
                None => unicode_str.push('\u{FFFD}'), // Replace invalid character with Unicode replacement character
            }
        }

        Ok(unicode_str)
    }

    /// Check if the end of data has been reached
    ///
    /// # Returns
    /// * `bool` - Returns true if the current position has reached or exceeded the end of data, otherwise false
    pub fn is_end(&self) -> bool {
        self.cursor.position() >= self.cursor.get_ref().len() as u64
    }

    /// Get the total data length
    ///
    /// # Returns
    /// * `u64` - Total number of bytes in the data
    pub fn get_length(&self) -> u64 {
        self.cursor.get_ref().len() as u64
    }
}
