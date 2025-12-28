//! WebDAV metadata implementation for vault entries.
//!
//! This module provides the `DavMetaData` trait implementation for vault
//! files, directories, and symlinks.

use dav_server::fs::{DavMetaData, FsError};
use oxidized_cryptolib::vault::operations::{VaultDirectoryInfo, VaultFileInfo, VaultSymlinkInfo};
use std::time::SystemTime;

/// Metadata for a vault entry (file, directory, or symlink).
#[derive(Debug, Clone)]
pub enum CryptomatorMetaData {
    /// Root directory metadata.
    Root,
    /// File metadata.
    File(FileMetaData),
    /// Directory metadata.
    Directory(DirectoryMetaData),
    /// Symlink metadata (exposed as regular file in WebDAV).
    Symlink(SymlinkMetaData),
}

/// Metadata for a file.
#[derive(Debug, Clone)]
pub struct FileMetaData {
    /// Decrypted filename.
    pub name: String,
    /// Plaintext file size (computed from encrypted size).
    pub size: u64,
    /// Modification time (from encrypted file).
    pub modified: SystemTime,
}

/// Metadata for a directory.
#[derive(Debug, Clone)]
pub struct DirectoryMetaData {
    /// Decrypted directory name.
    pub name: String,
    /// Modification time (from encrypted directory structure).
    pub modified: SystemTime,
}

/// Metadata for a symlink (treated as a regular file in WebDAV).
#[derive(Debug, Clone)]
pub struct SymlinkMetaData {
    /// Decrypted symlink name.
    pub name: String,
    /// Target path length (symlink content size).
    pub size: u64,
    /// Modification time.
    pub modified: SystemTime,
}

impl CryptomatorMetaData {
    /// Create metadata for the root directory.
    pub fn root() -> Self {
        CryptomatorMetaData::Root
    }

    /// Create metadata from a VaultFileInfo.
    pub fn from_file(info: &VaultFileInfo) -> Self {
        // Compute plaintext size from encrypted size
        // Encrypted file structure: 68-byte header + ceil(plaintext_size / 32768) * (32768 + 48) bytes
        // For simplicity, we estimate: plaintext ≈ encrypted_size * 0.998 (header + tag overhead)
        let plaintext_size = Self::estimate_plaintext_size(info.encrypted_size);

        // Try to get the modification time from the encrypted file
        let modified = std::fs::metadata(&info.encrypted_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        CryptomatorMetaData::File(FileMetaData {
            name: info.name.clone(),
            size: plaintext_size,
            modified,
        })
    }

    /// Create metadata from a VaultDirectoryInfo.
    pub fn from_directory(info: &VaultDirectoryInfo) -> Self {
        let modified = std::fs::metadata(&info.encrypted_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        CryptomatorMetaData::Directory(DirectoryMetaData {
            name: info.name.clone(),
            modified,
        })
    }

    /// Create metadata from a VaultSymlinkInfo.
    pub fn from_symlink(info: &VaultSymlinkInfo) -> Self {
        let modified = std::fs::metadata(&info.encrypted_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        CryptomatorMetaData::Symlink(SymlinkMetaData {
            name: info.name.clone(),
            size: info.target.len() as u64,
            modified,
        })
    }

    /// Create metadata with a specific size (for write buffers).
    pub fn file_with_size(name: String, size: u64) -> Self {
        CryptomatorMetaData::File(FileMetaData {
            name,
            size,
            modified: SystemTime::now(),
        })
    }

    /// Estimate plaintext size from encrypted size.
    ///
    /// Cryptomator file structure:
    /// - 68-byte header (12B nonce + 40B encrypted header + 16B tag)
    /// - Chunks: ceil(plaintext / 32768) * (32768 + 28 + 16) bytes
    ///   where 28 = 12B nonce + 16B tag per chunk
    ///
    /// Reverse calculation:
    /// encrypted_content = encrypted_size - 68
    /// num_chunks = ceil(encrypted_content / 32812)
    /// plaintext = num_chunks * 32768 - padding (last chunk)
    fn estimate_plaintext_size(encrypted_size: u64) -> u64 {
        if encrypted_size <= 68 {
            return 0;
        }
        let content_size = encrypted_size - 68;
        let chunk_size = 32768u64 + 28 + 16; // plaintext + nonce + tag
        let num_chunks = content_size.div_ceil(chunk_size);

        // For the last chunk, we don't know exact size, so estimate
        if num_chunks == 0 {
            0
        } else {
            let full_chunks = num_chunks.saturating_sub(1);
            let last_encrypted = content_size - full_chunks * chunk_size;
            let last_plaintext = last_encrypted.saturating_sub(28 + 16);
            full_chunks * 32768 + last_plaintext
        }
    }
}

impl DavMetaData for CryptomatorMetaData {
    fn len(&self) -> u64 {
        match self {
            CryptomatorMetaData::Root => 0,
            CryptomatorMetaData::File(f) => f.size,
            CryptomatorMetaData::Directory(_) => 0,
            CryptomatorMetaData::Symlink(s) => s.size,
        }
    }

    fn modified(&self) -> Result<SystemTime, FsError> {
        let time = match self {
            CryptomatorMetaData::Root => SystemTime::now(),
            CryptomatorMetaData::File(f) => f.modified,
            CryptomatorMetaData::Directory(d) => d.modified,
            CryptomatorMetaData::Symlink(s) => s.modified,
        };
        Ok(time)
    }

    fn is_dir(&self) -> bool {
        matches!(
            self,
            CryptomatorMetaData::Root | CryptomatorMetaData::Directory(_)
        )
    }

    fn is_file(&self) -> bool {
        matches!(
            self,
            CryptomatorMetaData::File(_) | CryptomatorMetaData::Symlink(_)
        )
    }

    fn is_symlink(&self) -> bool {
        // WebDAV doesn't support symlinks natively, so we expose them as files
        false
    }

    fn created(&self) -> Result<SystemTime, FsError> {
        // Cryptomator doesn't store creation time, return modification time
        self.modified()
    }

    fn accessed(&self) -> Result<SystemTime, FsError> {
        // Cryptomator doesn't store access time, return modification time
        self.modified()
    }

    fn status_changed(&self) -> Result<SystemTime, FsError> {
        // Cryptomator doesn't store status change time, return modification time
        self.modified()
    }

    fn executable(&self) -> Result<bool, FsError> {
        // Cryptomator doesn't store executable bit
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_metadata() {
        let meta = CryptomatorMetaData::root();
        assert!(meta.is_dir());
        assert!(!meta.is_file());
        assert_eq!(meta.len(), 0);
    }

    #[test]
    fn test_file_metadata() {
        let meta = CryptomatorMetaData::file_with_size("test.txt".to_string(), 1024);
        assert!(meta.is_file());
        assert!(!meta.is_dir());
        assert_eq!(meta.len(), 1024);
    }

    #[test]
    fn test_plaintext_size_estimation() {
        // Empty file: 68 bytes encrypted
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(68), 0);

        // File smaller than one chunk
        // e.g., 100 bytes plaintext = 68 + 100 + 28 + 16 = 212 bytes encrypted
        // But our estimation is approximate
        let small_encrypted = 68 + 100 + 44; // header + plaintext + overhead
        let estimated = CryptomatorMetaData::estimate_plaintext_size(small_encrypted);
        assert!(estimated <= 100 + 10); // Allow some margin

        // Very small encrypted file
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(50), 0);
    }
}
