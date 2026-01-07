//! Item identifier encoding and types for File Provider.
//!
//! File Provider requires stable string identifiers for all items.
//! We use base64url-encoded vault paths for this purpose.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use thiserror::Error;

/// Root item identifier (empty path)
pub const ROOT_ITEM_IDENTIFIER: &str = "cm9vdA";  // base64url("root")

/// Working set container identifier
#[allow(dead_code)]
pub const WORKING_SET_IDENTIFIER: &str = ".workingset";

/// Trash container identifier
#[allow(dead_code)]
pub const TRASH_IDENTIFIER: &str = ".trash";

/// Item type for File Provider items
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ItemType {
    /// Regular file
    File = 0,
    /// Directory
    Directory = 1,
    /// Symbolic link
    Symlink = 2,
}

impl From<u8> for ItemType {
    fn from(value: u8) -> Self {
        match value {
            1 => ItemType::Directory,
            2 => ItemType::Symlink,
            _ => ItemType::File, // 0 or any other value defaults to File
        }
    }
}

impl From<ItemType> for u8 {
    fn from(value: ItemType) -> Self {
        value as u8
    }
}

/// Error type for item identifier operations
#[derive(Debug, Error)]
pub enum ItemIdError {
    /// Failed to decode base64
    #[error("invalid base64 encoding: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Decoded bytes are not valid UTF-8
    #[error("invalid UTF-8 in identifier: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Invalid path format
    #[error("invalid path format: {0}")]
    InvalidPath(String),
}

/// Encode a vault path to a File Provider item identifier.
///
/// Uses base64url encoding (URL-safe, no padding) to ensure the identifier
/// is safe for use in URLs and file paths.
///
/// # Examples
///
/// ```
/// use oxcrypt_fileprovider::encode_identifier;
///
/// let id = encode_identifier("/Documents/file.txt");
/// assert!(!id.contains('/'));  // Safe for URLs
/// ```
pub fn encode_identifier(vault_path: &str) -> String {
    if vault_path.is_empty() || vault_path == "/" {
        return ROOT_ITEM_IDENTIFIER.to_string();
    }
    URL_SAFE_NO_PAD.encode(vault_path.as_bytes())
}

/// Decode a File Provider item identifier back to a vault path.
///
/// # Errors
///
/// Returns an error if the identifier is not valid base64url or
/// the decoded bytes are not valid UTF-8.
///
/// # Examples
///
/// ```
/// use oxcrypt_fileprovider::{encode_identifier, decode_identifier};
///
/// let path = "/Documents/file.txt";
/// let id = encode_identifier(path);
/// let decoded = decode_identifier(&id).unwrap();
/// assert_eq!(decoded, path);
/// ```
pub fn decode_identifier(identifier: &str) -> Result<String, ItemIdError> {
    // Handle special identifiers
    if identifier == ROOT_ITEM_IDENTIFIER {
        return Ok("/".to_string());
    }

    let bytes = URL_SAFE_NO_PAD.decode(identifier)?;
    let path = String::from_utf8(bytes)?;

    // Validate path format
    if !path.starts_with('/') && !path.is_empty() {
        return Err(ItemIdError::InvalidPath(format!(
            "path must start with '/': {path}"
        )));
    }

    Ok(path)
}

/// Compute the parent identifier from a vault path.
pub fn parent_identifier(vault_path: &str) -> String {
    if vault_path.is_empty() || vault_path == "/" {
        return ROOT_ITEM_IDENTIFIER.to_string();
    }

    let path = vault_path.trim_end_matches('/');
    if let Some(last_slash) = path.rfind('/') {
        let parent = &path[..last_slash];
        if parent.is_empty() {
            ROOT_ITEM_IDENTIFIER.to_string()
        } else {
            encode_identifier(parent)
        }
    } else {
        ROOT_ITEM_IDENTIFIER.to_string()
    }
}

/// Extract filename from a vault path.
pub fn filename_from_path(vault_path: &str) -> String {
    let path = vault_path.trim_end_matches('/');
    if path.is_empty() || path == "/" {
        return String::new();
    }

    path.rsplit('/').next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let paths = vec![
            "/",
            "/Documents",
            "/Documents/file.txt",
            "/path with spaces/file.txt",
            "/unicode/文件.txt",
        ];

        for path in paths {
            let encoded = encode_identifier(path);
            let decoded = decode_identifier(&encoded).unwrap();

            // Normalize root path
            let expected = if path == "/" { "/" } else { path };
            assert_eq!(decoded, expected, "roundtrip failed for: {path}");
        }
    }

    #[test]
    fn test_root_identifier() {
        assert_eq!(encode_identifier("/"), ROOT_ITEM_IDENTIFIER);
        assert_eq!(encode_identifier(""), ROOT_ITEM_IDENTIFIER);
        assert_eq!(decode_identifier(ROOT_ITEM_IDENTIFIER).unwrap(), "/");
    }

    #[test]
    fn test_parent_identifier() {
        assert_eq!(parent_identifier("/"), ROOT_ITEM_IDENTIFIER);
        assert_eq!(parent_identifier("/Documents"), ROOT_ITEM_IDENTIFIER);
        assert_eq!(
            parent_identifier("/Documents/file.txt"),
            encode_identifier("/Documents")
        );
    }

    #[test]
    fn test_filename_extraction() {
        assert_eq!(filename_from_path("/"), "");
        assert_eq!(filename_from_path("/Documents"), "Documents");
        assert_eq!(filename_from_path("/Documents/file.txt"), "file.txt");
        assert_eq!(filename_from_path("/Documents/"), "Documents");
    }
}
