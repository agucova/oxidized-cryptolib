//! Pure helper functions shared between sync and async vault operations.
//!
//! This module contains functions that have no I/O and can be used by both
//! `VaultOperations` (sync) and `VaultOperationsAsync` without modification.

use std::path::{Path, PathBuf};

use crate::crypto::keys::MasterKey;
use crate::fs::name::{create_c9s_filename, hash_dir_id, NameError};
use crate::vault::path::DirId;

// ============================================================================
// Entry Lookup Path Calculation
// ============================================================================

/// Pre-computed paths for looking up a file or directory entry.
///
/// This struct contains all the path information needed to check if an entry
/// exists, without performing any I/O. Both sync and async implementations
/// use this to separate pure path calculation from filesystem operations.
#[derive(Debug, Clone)]
pub struct EntryPaths {
    /// The encrypted filename (base64url encoded).
    pub encrypted_name: String,
    /// Whether this name exceeds the shortening threshold.
    pub is_shortened: bool,
    /// Path to the .c9r or .c9s entry itself.
    pub entry_path: PathBuf,
    /// Path to check for existence (contents.c9r for shortened files,
    /// dir.c9r for directories, or the .c9r file itself for regular files).
    pub content_path: PathBuf,
}

/// Calculate paths for looking up a file by its encrypted name.
///
/// For regular files (.c9r format):
/// - `entry_path` = `storage_path/{encrypted_name}.c9r`
/// - `content_path` = same as `entry_path` (the file itself)
///
/// For shortened files (.c9s format):
/// - `entry_path` = `storage_path/{hash}.c9s`
/// - `content_path` = `storage_path/{hash}.c9s/contents.c9r`
///
/// # Arguments
///
/// * `storage_path` - The parent directory's storage path (from `calculate_directory_storage_path`)
/// * `encrypted_name` - The encrypted filename to look up
/// * `shortening_threshold` - Names longer than this use .c9s format
pub fn calculate_file_lookup_paths(
    storage_path: &Path,
    encrypted_name: &str,
    shortening_threshold: usize,
) -> EntryPaths {
    let is_shortened = encrypted_name.len() > shortening_threshold;

    if is_shortened {
        let hash = create_c9s_filename(encrypted_name);
        let entry_path = storage_path.join(format!("{hash}.c9s"));
        let content_path = entry_path.join("contents.c9r");
        EntryPaths {
            encrypted_name: encrypted_name.to_string(),
            is_shortened: true,
            entry_path,
            content_path,
        }
    } else {
        let entry_path = storage_path.join(format!("{encrypted_name}.c9r"));
        EntryPaths {
            encrypted_name: encrypted_name.to_string(),
            is_shortened: false,
            content_path: entry_path.clone(),
            entry_path,
        }
    }
}

/// Calculate paths for looking up a directory by its encrypted name.
///
/// For regular directories (.c9r format):
/// - `entry_path` = `storage_path/{encrypted_name}.c9r`
/// - `content_path` = `storage_path/{encrypted_name}.c9r/dir.c9r`
///
/// For shortened directories (.c9s format):
/// - `entry_path` = `storage_path/{hash}.c9s`
/// - `content_path` = `storage_path/{hash}.c9s/dir.c9r`
///
/// # Arguments
///
/// * `storage_path` - The parent directory's storage path (from `calculate_directory_storage_path`)
/// * `encrypted_name` - The encrypted directory name to look up
/// * `shortening_threshold` - Names longer than this use .c9s format
pub fn calculate_directory_lookup_paths(
    storage_path: &Path,
    encrypted_name: &str,
    shortening_threshold: usize,
) -> EntryPaths {
    let is_shortened = encrypted_name.len() > shortening_threshold;

    if is_shortened {
        let hash = create_c9s_filename(encrypted_name);
        let entry_path = storage_path.join(format!("{hash}.c9s"));
        let content_path = entry_path.join("dir.c9r");
        EntryPaths {
            encrypted_name: encrypted_name.to_string(),
            is_shortened: true,
            entry_path,
            content_path,
        }
    } else {
        let entry_path = storage_path.join(format!("{encrypted_name}.c9r"));
        let content_path = entry_path.join("dir.c9r");
        EntryPaths {
            encrypted_name: encrypted_name.to_string(),
            is_shortened: false,
            entry_path,
            content_path,
        }
    }
}

/// Calculate paths for looking up a symlink by its encrypted name.
///
/// For regular symlinks (.c9r format):
/// - `entry_path` = `storage_path/{encrypted_name}.c9r`
/// - `content_path` = `storage_path/{encrypted_name}.c9r/symlink.c9r`
///
/// For shortened symlinks (.c9s format):
/// - `entry_path` = `storage_path/{hash}.c9s`
/// - `content_path` = `storage_path/{hash}.c9s/symlink.c9r`
///
/// # Arguments
///
/// * `storage_path` - The parent directory's storage path (from `calculate_directory_storage_path`)
/// * `encrypted_name` - The encrypted symlink name to look up
/// * `shortening_threshold` - Names longer than this use .c9s format
pub fn calculate_symlink_lookup_paths(
    storage_path: &Path,
    encrypted_name: &str,
    shortening_threshold: usize,
) -> EntryPaths {
    let is_shortened = encrypted_name.len() > shortening_threshold;

    if is_shortened {
        let hash = create_c9s_filename(encrypted_name);
        let entry_path = storage_path.join(format!("{hash}.c9s"));
        let content_path = entry_path.join("symlink.c9r");
        EntryPaths {
            encrypted_name: encrypted_name.to_string(),
            is_shortened: true,
            entry_path,
            content_path,
        }
    } else {
        let entry_path = storage_path.join(format!("{encrypted_name}.c9r"));
        let content_path = entry_path.join("symlink.c9r");
        EntryPaths {
            encrypted_name: encrypted_name.to_string(),
            is_shortened: false,
            entry_path,
            content_path,
        }
    }
}

// ============================================================================
// Directory Storage Path Calculation
// ============================================================================

/// Calculate the storage path for a directory given its ID.
///
/// The path is constructed as: `vault_path/d/{first_two_chars}/{remaining_chars}`
/// where the hash is derived from the directory ID using the master key.
///
/// # Arguments
///
/// * `vault_path` - The root path of the vault
/// * `dir_id` - The directory ID to calculate the path for
/// * `master_key` - The master key for hashing
///
/// # Returns
///
/// The full path to the directory's storage location, or an error if hashing fails.
pub fn calculate_directory_storage_path(
    vault_path: &Path,
    dir_id: &DirId,
    master_key: &MasterKey,
) -> Result<PathBuf, StoragePathError> {
    let hashed = hash_dir_id(dir_id.as_str(), master_key)?;
    let hash_chars: Vec<char> = hashed.chars().collect();

    if hash_chars.len() < 32 {
        return Err(StoragePathError::HashTooShort {
            length: hash_chars.len(),
            dir_id: dir_id.as_str().to_string(),
        });
    }

    let first_two: String = hash_chars[0..2].iter().collect();
    let remaining: String = hash_chars[2..32].iter().collect();

    Ok(vault_path.join("d").join(&first_two).join(&remaining))
}

/// Parse a vault path into its components.
///
/// Splits the path by '/' and filters out empty segments.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(parse_path_components("/foo/bar"), vec!["foo", "bar"]);
/// assert_eq!(parse_path_components("foo/bar/"), vec!["foo", "bar"]);
/// assert_eq!(parse_path_components("/"), Vec::<&str>::new());
/// ```
#[inline]
pub fn parse_path_components(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Check if an encrypted filename needs shortening.
///
/// Filenames longer than the threshold use the `.c9s` format instead of `.c9r`.
#[inline]
pub fn needs_shortening(encrypted_name: &str, threshold: usize) -> bool {
    encrypted_name.len() > threshold
}

/// Extract the base name from a `.c9r` or `.c9s` filename.
///
/// Returns `None` if the filename doesn't have a recognized extension.
pub fn extract_encrypted_base_name(filename: &str) -> Option<&str> {
    if let Some(base) = filename.strip_suffix(".c9r") {
        Some(base)
    } else if let Some(base) = filename.strip_suffix(".c9s") {
        Some(base)
    } else {
        None
    }
}

/// Check if a path represents a shortened entry (`.c9s` format).
#[inline]
pub fn is_shortened_entry(filename: &str) -> bool {
    filename.ends_with(".c9s")
}

/// Check if a path represents a regular encrypted entry (`.c9r` format).
#[inline]
pub fn is_regular_entry(filename: &str) -> bool {
    filename.ends_with(".c9r")
}

/// Determine the entry type from a `.c9r` directory's contents.
///
/// A `.c9r` directory can contain:
/// - `dir.c9r` - indicates a directory
/// - `symlink.c9r` - indicates a symlink
/// - Neither - indicates a regular file (the directory itself is the file container)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C9rEntryType {
    /// The entry is a directory (contains `dir.c9r`)
    Directory,
    /// The entry is a symlink (contains `symlink.c9r`)
    Symlink,
    /// The entry is a regular file
    File,
}

// ============================================================================
// Entry Marker Constants
// ============================================================================

/// Marker file inside a `.c9r` directory indicating it's a directory entry.
pub const DIR_MARKER: &str = "dir.c9r";

/// Marker file inside a `.c9r` directory indicating it's a symlink entry.
pub const SYMLINK_MARKER: &str = "symlink.c9r";

/// Content file inside a `.c9s` directory for shortened files.
pub const CONTENTS_FILE: &str = "contents.c9r";

/// Name file inside a `.c9s` directory storing the original encrypted name.
pub const NAME_FILE: &str = "name.c9s";

// ============================================================================
// Entry Classification
// ============================================================================

/// Result of classifying a vault entry by its filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryFormat {
    /// Regular encrypted entry (`.c9r` extension)
    Regular,
    /// Shortened entry (`.c9s` extension, name exceeded threshold)
    Shortened,
}

/// Classify an entry by its filename extension and extract the base name.
///
/// Returns `None` if the filename doesn't have a recognized vault extension.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(
///     classify_entry_format("encrypted_name.c9r"),
///     Some((EntryFormat::Regular, "encrypted_name"))
/// );
/// assert_eq!(
///     classify_entry_format("abc123.c9s"),
///     Some((EntryFormat::Shortened, "abc123"))
/// );
/// assert_eq!(classify_entry_format("not_a_vault_file.txt"), None);
/// ```
#[inline]
pub fn classify_entry_format(filename: &str) -> Option<(EntryFormat, &str)> {
    if let Some(base) = filename.strip_suffix(".c9r") {
        Some((EntryFormat::Regular, base))
    } else if let Some(base) = filename.strip_suffix(".c9s") {
        Some((EntryFormat::Shortened, base))
    } else {
        None
    }
}

/// Errors that can occur during storage path calculation.
#[derive(Debug, thiserror::Error)]
pub enum StoragePathError {
    #[error("Hashed directory ID is too short ({length} chars) for dir_id: {dir_id}")]
    HashTooShort { length: usize, dir_id: String },

    #[error("Name hashing error: {0}")]
    NameError(#[from] NameError),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Entry Lookup Path Tests
    // ========================================================================

    #[test]
    fn test_calculate_file_lookup_paths_regular() {
        let storage = Path::new("/vault/d/AB/CDEF");
        let paths = calculate_file_lookup_paths(storage, "encrypted_name", 220);

        assert!(!paths.is_shortened);
        assert_eq!(paths.encrypted_name, "encrypted_name");
        assert_eq!(
            paths.entry_path,
            PathBuf::from("/vault/d/AB/CDEF/encrypted_name.c9r")
        );
        // For regular files, content_path == entry_path
        assert_eq!(paths.content_path, paths.entry_path);
    }

    #[test]
    fn test_calculate_file_lookup_paths_shortened() {
        let storage = Path::new("/vault/d/AB/CDEF");
        let long_name = "a".repeat(250);
        let paths = calculate_file_lookup_paths(storage, &long_name, 220);

        assert!(paths.is_shortened);
        assert_eq!(paths.encrypted_name, long_name);
        // Entry path should be a .c9s directory
        assert!(paths.entry_path.to_string_lossy().ends_with(".c9s"));
        // Content path should be contents.c9r inside
        assert!(paths.content_path.to_string_lossy().ends_with("contents.c9r"));
        assert!(paths.content_path.starts_with(&paths.entry_path));
    }

    #[test]
    fn test_calculate_file_lookup_paths_boundary() {
        let storage = Path::new("/vault/d/AB/CDEF");

        // Exactly at threshold - should NOT be shortened
        let at_threshold = "a".repeat(220);
        let paths = calculate_file_lookup_paths(storage, &at_threshold, 220);
        assert!(!paths.is_shortened);

        // One over threshold - SHOULD be shortened
        let over_threshold = "a".repeat(221);
        let paths = calculate_file_lookup_paths(storage, &over_threshold, 220);
        assert!(paths.is_shortened);
    }

    #[test]
    fn test_calculate_directory_lookup_paths_regular() {
        let storage = Path::new("/vault/d/AB/CDEF");
        let paths = calculate_directory_lookup_paths(storage, "encrypted_dir", 220);

        assert!(!paths.is_shortened);
        assert_eq!(paths.encrypted_name, "encrypted_dir");
        assert_eq!(
            paths.entry_path,
            PathBuf::from("/vault/d/AB/CDEF/encrypted_dir.c9r")
        );
        // For directories, content_path is dir.c9r inside
        assert_eq!(
            paths.content_path,
            PathBuf::from("/vault/d/AB/CDEF/encrypted_dir.c9r/dir.c9r")
        );
    }

    #[test]
    fn test_calculate_directory_lookup_paths_shortened() {
        let storage = Path::new("/vault/d/AB/CDEF");
        let long_name = "b".repeat(250);
        let paths = calculate_directory_lookup_paths(storage, &long_name, 220);

        assert!(paths.is_shortened);
        assert_eq!(paths.encrypted_name, long_name);
        // Entry path should be a .c9s directory
        assert!(paths.entry_path.to_string_lossy().ends_with(".c9s"));
        // Content path should be dir.c9r inside
        assert!(paths.content_path.to_string_lossy().ends_with("dir.c9r"));
        assert!(paths.content_path.starts_with(&paths.entry_path));
    }

    // ========================================================================
    // Path Component Tests
    // ========================================================================

    #[test]
    fn test_parse_path_components() {
        assert_eq!(parse_path_components("/foo/bar"), vec!["foo", "bar"]);
        assert_eq!(parse_path_components("foo/bar/"), vec!["foo", "bar"]);
        assert_eq!(parse_path_components("/"), Vec::<&str>::new());
        assert_eq!(parse_path_components(""), Vec::<&str>::new());
        assert_eq!(parse_path_components("single"), vec!["single"]);
        assert_eq!(
            parse_path_components("//double//slash//"),
            vec!["double", "slash"]
        );
    }

    #[test]
    fn test_needs_shortening() {
        assert!(!needs_shortening("short", 220));
        assert!(!needs_shortening(&"a".repeat(220), 220));
        assert!(needs_shortening(&"a".repeat(221), 220));
    }

    #[test]
    fn test_extract_encrypted_base_name() {
        assert_eq!(extract_encrypted_base_name("test.c9r"), Some("test"));
        assert_eq!(extract_encrypted_base_name("test.c9s"), Some("test"));
        assert_eq!(extract_encrypted_base_name("test.txt"), None);
        assert_eq!(extract_encrypted_base_name("test"), None);
    }

    #[test]
    fn test_is_shortened_entry() {
        assert!(is_shortened_entry("abc123.c9s"));
        assert!(!is_shortened_entry("abc123.c9r"));
        assert!(!is_shortened_entry("abc123"));
    }

    #[test]
    fn test_is_regular_entry() {
        assert!(is_regular_entry("abc123.c9r"));
        assert!(!is_regular_entry("abc123.c9s"));
        assert!(!is_regular_entry("abc123"));
    }

    // ========================================================================
    // Entry Classification Tests
    // ========================================================================

    #[test]
    fn test_classify_entry_format_regular() {
        let result = classify_entry_format("encrypted_name.c9r");
        assert_eq!(result, Some((EntryFormat::Regular, "encrypted_name")));
    }

    #[test]
    fn test_classify_entry_format_shortened() {
        let result = classify_entry_format("abc123def.c9s");
        assert_eq!(result, Some((EntryFormat::Shortened, "abc123def")));
    }

    #[test]
    fn test_classify_entry_format_not_vault() {
        assert_eq!(classify_entry_format("regular_file.txt"), None);
        assert_eq!(classify_entry_format("no_extension"), None);
        assert_eq!(classify_entry_format(".c9r"), Some((EntryFormat::Regular, "")));
    }

    #[test]
    fn test_marker_constants() {
        // Ensure constants match expected Cryptomator format
        assert_eq!(DIR_MARKER, "dir.c9r");
        assert_eq!(SYMLINK_MARKER, "symlink.c9r");
        assert_eq!(CONTENTS_FILE, "contents.c9r");
        assert_eq!(NAME_FILE, "name.c9s");
    }
}
