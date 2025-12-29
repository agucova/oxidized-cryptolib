//! WebDAV metadata implementation for vault entries.
//!
//! This module provides the `DavMetaData` trait implementation for vault
//! files, directories, and symlinks.

#![allow(dead_code)] // Metadata fields used for Debug/Clone traits

use dav_server::fs::{DavMetaData, FsError};
use oxcrypt_core::vault::operations::{VaultDirectoryInfo, VaultFileInfo, VaultSymlinkInfo};
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
    /// - Chunks: each chunk is nonce (12B) + plaintext (up to 32KB) + tag (16B)
    ///   Overhead per chunk = 28 bytes (12 + 16)
    ///
    /// Reverse calculation:
    /// encrypted_content = encrypted_size - 68
    /// For last chunk: encrypted_chunk_size = plaintext_size + 28
    fn estimate_plaintext_size(encrypted_size: u64) -> u64 {
        const HEADER_SIZE: u64 = 68;
        const CHUNK_OVERHEAD: u64 = 28; // 12B nonce + 16B tag
        const MAX_PLAINTEXT_CHUNK: u64 = 32768;
        const MAX_ENCRYPTED_CHUNK: u64 = MAX_PLAINTEXT_CHUNK + CHUNK_OVERHEAD; // 32796

        if encrypted_size <= HEADER_SIZE {
            return 0;
        }

        let content_size = encrypted_size - HEADER_SIZE;

        // Calculate number of full chunks and remainder
        let num_full_chunks = content_size / MAX_ENCRYPTED_CHUNK;
        let remainder = content_size % MAX_ENCRYPTED_CHUNK;

        // Full chunks contribute MAX_PLAINTEXT_CHUNK each
        let full_chunk_plaintext = num_full_chunks * MAX_PLAINTEXT_CHUNK;

        // Remainder is the last (possibly partial) chunk
        let last_chunk_plaintext = if remainder > CHUNK_OVERHEAD {
            remainder - CHUNK_OVERHEAD
        } else if remainder > 0 {
            // Edge case: remainder exists but is smaller than overhead
            // This shouldn't happen with valid Cryptomator files
            0
        } else {
            0
        };

        full_chunk_plaintext + last_chunk_plaintext
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
        // Header only (empty file): 68 bytes encrypted
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(68), 0);

        // Very small encrypted file (smaller than header)
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(50), 0);

        // Small file: 7 bytes plaintext
        // encrypted = 68 (header) + 12 (nonce) + 7 (plaintext) + 16 (tag) = 103
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(103), 7);

        // 100 bytes plaintext
        // encrypted = 68 + 12 + 100 + 16 = 196
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(196), 100);

        // Exactly one full chunk: 32768 bytes plaintext
        // encrypted = 68 + 12 + 32768 + 16 = 32864
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(32864), 32768);

        // One full chunk + 100 bytes: 32868 bytes plaintext
        // encrypted = 68 + 32796 (full chunk) + 12 + 100 + 16 = 68 + 32796 + 128 = 32992
        assert_eq!(CryptomatorMetaData::estimate_plaintext_size(32992), 32868);
    }
}
