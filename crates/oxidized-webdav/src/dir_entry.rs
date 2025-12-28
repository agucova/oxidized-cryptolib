//! WebDAV directory entry implementation for vault entries.
//!
//! This module provides the `DavDirEntry` trait implementation for vault
//! files, directories, and symlinks.

use crate::metadata::CryptomatorMetaData;
use dav_server::fs::{DavDirEntry, DavMetaData, FsFuture};
use oxidized_cryptolib::vault::operations::{VaultDirectoryInfo, VaultFileInfo, VaultSymlinkInfo};
use std::time::SystemTime;

/// A directory entry in the vault.
#[derive(Debug, Clone)]
pub enum CryptomatorDirEntry {
    /// A file entry.
    File(VaultFileInfo),
    /// A directory entry.
    Directory(VaultDirectoryInfo),
    /// A symlink entry (exposed as regular file).
    Symlink(VaultSymlinkInfo),
}

impl CryptomatorDirEntry {
    /// Create a file entry.
    pub fn file(info: VaultFileInfo) -> Self {
        CryptomatorDirEntry::File(info)
    }

    /// Create a directory entry.
    pub fn directory(info: VaultDirectoryInfo) -> Self {
        CryptomatorDirEntry::Directory(info)
    }

    /// Create a symlink entry.
    pub fn symlink(info: VaultSymlinkInfo) -> Self {
        CryptomatorDirEntry::Symlink(info)
    }
}

impl DavDirEntry for CryptomatorDirEntry {
    fn name(&self) -> Vec<u8> {
        match self {
            CryptomatorDirEntry::File(f) => f.name.as_bytes().to_vec(),
            CryptomatorDirEntry::Directory(d) => d.name.as_bytes().to_vec(),
            CryptomatorDirEntry::Symlink(s) => s.name.as_bytes().to_vec(),
        }
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: CryptomatorMetaData = match self {
            CryptomatorDirEntry::File(f) => CryptomatorMetaData::from_file(f),
            CryptomatorDirEntry::Directory(d) => CryptomatorMetaData::from_directory(d),
            CryptomatorDirEntry::Symlink(s) => CryptomatorMetaData::from_symlink(s),
        };
        Box::pin(async move { Ok(Box::new(meta) as Box<dyn DavMetaData>) })
    }

    fn is_dir(&self) -> FsFuture<'_, bool> {
        let is_dir = matches!(self, CryptomatorDirEntry::Directory(_));
        Box::pin(async move { Ok(is_dir) })
    }

    fn is_file(&self) -> FsFuture<'_, bool> {
        let is_file = matches!(
            self,
            CryptomatorDirEntry::File(_) | CryptomatorDirEntry::Symlink(_)
        );
        Box::pin(async move { Ok(is_file) })
    }

    fn is_symlink(&self) -> FsFuture<'_, bool> {
        // WebDAV doesn't support symlinks, expose them as files
        Box::pin(async { Ok(false) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_cryptolib::vault::DirId;
    use std::path::PathBuf;

    fn test_file_info() -> VaultFileInfo {
        VaultFileInfo {
            name: "test.txt".to_string(),
            encrypted_name: "ABCD1234.c9r".to_string(),
            encrypted_path: PathBuf::from("/vault/d/AB/CD/ABCD1234.c9r"),
            encrypted_size: 1024,
            is_shortened: false,
        }
    }

    fn test_dir_info() -> VaultDirectoryInfo {
        VaultDirectoryInfo {
            name: "subdir".to_string(),
            directory_id: DirId::from_raw("some-uuid"),
            encrypted_path: PathBuf::from("/vault/d/EF/GH/EFGH5678.c9r"),
            parent_directory_id: DirId::root(),
        }
    }

    #[test]
    fn test_file_entry_name() {
        let entry = CryptomatorDirEntry::file(test_file_info());
        assert_eq!(entry.name(), b"test.txt");
    }

    #[test]
    fn test_dir_entry_name() {
        let entry = CryptomatorDirEntry::directory(test_dir_info());
        assert_eq!(entry.name(), b"subdir");
    }

    #[tokio::test]
    async fn test_file_entry_is_file() {
        let entry = CryptomatorDirEntry::file(test_file_info());
        assert!(entry.is_file().await.unwrap());
        assert!(!entry.is_dir().await.unwrap());
    }

    #[tokio::test]
    async fn test_dir_entry_is_dir() {
        let entry = CryptomatorDirEntry::directory(test_dir_info());
        assert!(entry.is_dir().await.unwrap());
        assert!(!entry.is_file().await.unwrap());
    }
}
