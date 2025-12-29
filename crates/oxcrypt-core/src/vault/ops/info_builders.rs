//! Builder functions for vault info structs.
//!
//! These functions provide a single location for constructing `VaultFileInfo`,
//! `VaultDirectoryInfo`, and `VaultSymlinkInfo` structs. Both sync and async
//! implementations use these to ensure consistency.

use std::path::PathBuf;

use crate::vault::path::DirId;

// Import the info structs from operations module
use crate::vault::operations::{VaultDirectoryInfo, VaultFileInfo, VaultSymlinkInfo};

/// Build a `VaultFileInfo` from its components.
///
/// This is the canonical way to construct file info in both sync and async
/// implementations, ensuring field assignment consistency.
#[inline]
pub fn build_file_info(
    name: String,
    encrypted_name: String,
    encrypted_path: PathBuf,
    encrypted_size: u64,
    is_shortened: bool,
) -> VaultFileInfo {
    VaultFileInfo {
        name,
        encrypted_name,
        encrypted_path,
        encrypted_size,
        is_shortened,
    }
}

/// Build a `VaultDirectoryInfo` from its components.
///
/// This is the canonical way to construct directory info in both sync and async
/// implementations, ensuring field assignment consistency.
#[inline]
pub fn build_directory_info(
    name: String,
    directory_id: DirId,
    encrypted_path: PathBuf,
    parent_directory_id: DirId,
) -> VaultDirectoryInfo {
    VaultDirectoryInfo {
        name,
        directory_id,
        encrypted_path,
        parent_directory_id,
    }
}

/// Build a `VaultSymlinkInfo` from its components.
///
/// This is the canonical way to construct symlink info in both sync and async
/// implementations, ensuring field assignment consistency.
#[inline]
pub fn build_symlink_info(
    name: String,
    target: String,
    encrypted_path: PathBuf,
    is_shortened: bool,
) -> VaultSymlinkInfo {
    VaultSymlinkInfo {
        name,
        target,
        encrypted_path,
        is_shortened,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_file_info() {
        let info = build_file_info(
            "test.txt".to_string(),
            "encrypted_name".to_string(),
            PathBuf::from("/vault/d/AB/CD/encrypted.c9r"),
            1024,
            false,
        );

        assert_eq!(info.name, "test.txt");
        assert_eq!(info.encrypted_name, "encrypted_name");
        assert_eq!(
            info.encrypted_path,
            PathBuf::from("/vault/d/AB/CD/encrypted.c9r")
        );
        assert_eq!(info.encrypted_size, 1024);
        assert!(!info.is_shortened);
    }

    #[test]
    fn test_build_file_info_shortened() {
        let info = build_file_info(
            "very_long_name.txt".to_string(),
            "abc123".to_string(),
            PathBuf::from("/vault/d/AB/CD/abc123.c9s/contents.c9r"),
            2048,
            true,
        );

        assert_eq!(info.name, "very_long_name.txt");
        assert!(info.is_shortened);
    }

    #[test]
    fn test_build_directory_info() {
        let dir_id = DirId::from_raw("test-uuid-1234");
        let parent_id = DirId::root();

        let info = build_directory_info(
            "docs".to_string(),
            dir_id.clone(),
            PathBuf::from("/vault/d/AB/CD/encrypted_docs.c9r"),
            parent_id.clone(),
        );

        assert_eq!(info.name, "docs");
        assert_eq!(info.directory_id, dir_id);
        assert_eq!(info.parent_directory_id, parent_id);
    }

    #[test]
    fn test_build_symlink_info() {
        let info = build_symlink_info(
            "link.txt".to_string(),
            "/target/path".to_string(),
            PathBuf::from("/vault/d/AB/CD/encrypted_link.c9r/symlink.c9r"),
            false,
        );

        assert_eq!(info.name, "link.txt");
        assert_eq!(info.target, "/target/path");
        assert!(!info.is_shortened);
    }
}
