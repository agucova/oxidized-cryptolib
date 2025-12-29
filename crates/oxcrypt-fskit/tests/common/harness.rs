//! Test harness for oxcrypt-fskit-ffi integration tests.
//!
//! This module provides [`TestFilesystem`], a wrapper around [`CryptoFilesystem`]
//! that simplifies testing by:
//!
//! - Automatically creating temporary vaults using `TempVault`
//! - Unwrapping FFI result wrappers into `Result<T, i32>` (errno)
//! - Providing convenience methods for common operations
//!
//! # Usage
//!
//! ```ignore
//! use crate::common::harness::TestFilesystem;
//!
//! #[test]
//! fn test_create_file() {
//!     let fs = TestFilesystem::new();
//!     let root = fs.root_id();
//!     let attrs = fs.create_file(root, "test.txt").unwrap();
//!     assert!(attrs.attr_is_file());
//! }
//! ```

use oxcrypt_fskit::{
    crypto_fs_new, CryptoFilesystem, DirectoryEntry, FileAttributes, VolumeStatistics,
};
use oxcrypt_mount::testing::{TempVault, TEST_PASSWORD};

/// Test wrapper around `CryptoFilesystem` for ergonomic testing.
///
/// This struct owns both the filesystem and the temporary vault, ensuring
/// proper cleanup when the test completes.
pub struct TestFilesystem {
    /// The underlying CryptoFilesystem instance.
    fs: CryptoFilesystem,
    /// Temporary vault (cleaned up on drop).
    _temp_vault: TempVault,
}

impl TestFilesystem {
    /// Creates a new test filesystem with a fresh temporary vault.
    ///
    /// # Panics
    ///
    /// Panics if the vault or filesystem cannot be created.
    pub fn new() -> Self {
        let temp_vault = TempVault::new();
        let vault_path = temp_vault.path().to_string_lossy().to_string();

        let result = crypto_fs_new(vault_path, TEST_PASSWORD.to_string());
        assert!(
            result.result_fs_is_ok(),
            "Failed to create CryptoFilesystem: errno {}",
            result.result_fs_error()
        );

        let fs = result.result_fs_unwrap();

        Self {
            fs,
            _temp_vault: temp_vault,
        }
    }

    /// Returns the root item ID (always 2 for FSKit).
    pub fn root_id(&self) -> u64 {
        self.fs.get_root_item_id()
    }

    /// Provides direct access to the underlying filesystem for advanced tests.
    pub fn inner(&self) -> &CryptoFilesystem {
        &self.fs
    }

    // ========================================================================
    // Lookup Operations
    // ========================================================================

    /// Looks up an item by name within a parent directory.
    ///
    /// Returns `Ok(FileAttributes)` on success, `Err(errno)` on failure.
    pub fn lookup(&self, parent_id: u64, name: &str) -> Result<FileAttributes, i32> {
        let result = self.fs.lookup(parent_id, name.to_string());
        if result.result_attrs_is_ok() {
            Ok(result.result_attrs_unwrap())
        } else {
            Err(result.result_attrs_error())
        }
    }

    /// Gets attributes of an item by its ID.
    ///
    /// Returns `Ok(FileAttributes)` on success, `Err(errno)` on failure.
    pub fn get_attributes(&self, item_id: u64) -> Result<FileAttributes, i32> {
        let result = self.fs.get_attributes(item_id);
        if result.result_attrs_is_ok() {
            Ok(result.result_attrs_unwrap())
        } else {
            Err(result.result_attrs_error())
        }
    }

    // ========================================================================
    // Directory Operations
    // ========================================================================

    /// Creates a new directory.
    ///
    /// Returns `Ok(FileAttributes)` for the new directory, `Err(errno)` on failure.
    pub fn create_directory(&self, parent_id: u64, name: &str) -> Result<FileAttributes, i32> {
        let result = self.fs.create_directory(parent_id, name.to_string());
        if result.result_attrs_is_ok() {
            Ok(result.result_attrs_unwrap())
        } else {
            Err(result.result_attrs_error())
        }
    }

    /// Enumerates directory contents.
    ///
    /// Returns entries starting from the given cookie (0 for start).
    pub fn enumerate_directory(
        &self,
        item_id: u64,
        cookie: u64,
    ) -> Result<Vec<DirectoryEntry>, i32> {
        let result = self.fs.enumerate_directory(item_id, cookie);
        if result.result_dir_is_ok() {
            Ok(result.result_dir_unwrap())
        } else {
            Err(result.result_dir_error())
        }
    }

    /// Gets the next enumeration cookie for pagination.
    pub fn get_enumeration_cookie(&self, item_id: u64, cookie: u64) -> u64 {
        self.fs.get_enumeration_cookie(item_id, cookie)
    }

    // ========================================================================
    // File Operations
    // ========================================================================

    /// Creates a new empty file.
    ///
    /// Returns `Ok(FileAttributes)` for the new file, `Err(errno)` on failure.
    pub fn create_file(&self, parent_id: u64, name: &str) -> Result<FileAttributes, i32> {
        let result = self.fs.create_file(parent_id, name.to_string());
        if result.result_attrs_is_ok() {
            Ok(result.result_attrs_unwrap())
        } else {
            Err(result.result_attrs_error())
        }
    }

    /// Opens a file for reading or writing.
    ///
    /// Returns `Ok(handle)` on success, `Err(errno)` on failure.
    pub fn open_file(&self, item_id: u64, for_write: bool) -> Result<u64, i32> {
        let result = self.fs.open_file(item_id, for_write);
        if result.result_handle_is_ok() {
            Ok(result.result_handle_unwrap())
        } else {
            Err(result.result_handle_error())
        }
    }

    /// Closes an open file handle.
    ///
    /// This flushes any pending writes to the vault.
    pub fn close_file(&self, handle: u64) -> Result<(), i32> {
        let result = self.fs.close_file(handle);
        if result.result_unit_is_ok() {
            Ok(())
        } else {
            Err(result.result_unit_error())
        }
    }

    /// Reads data from an open file handle.
    ///
    /// Returns `Ok(data)` on success, `Err(errno)` on failure.
    pub fn read_file(&self, handle: u64, offset: i64, length: i64) -> Result<Vec<u8>, i32> {
        let result = self.fs.read_file(handle, offset, length);
        if result.result_bytes_is_ok() {
            Ok(result.result_bytes_unwrap())
        } else {
            Err(result.result_bytes_error())
        }
    }

    /// Writes data to an open file handle.
    ///
    /// Returns `Ok(bytes_written)` on success, `Err(errno)` on failure.
    pub fn write_file(&self, handle: u64, offset: i64, data: &[u8]) -> Result<i64, i32> {
        let result = self.fs.write_file(handle, offset, data.to_vec());
        if result.result_written_is_ok() {
            Ok(result.result_written_unwrap())
        } else {
            Err(result.result_written_error())
        }
    }

    /// Truncates a file to the specified size.
    pub fn truncate(&self, item_id: u64, size: u64) -> Result<(), i32> {
        let result = self.fs.truncate(item_id, size);
        if result.result_unit_is_ok() {
            Ok(())
        } else {
            Err(result.result_unit_error())
        }
    }

    // ========================================================================
    // Symlink Operations
    // ========================================================================

    /// Creates a new symbolic link.
    ///
    /// Returns `Ok(FileAttributes)` for the new symlink, `Err(errno)` on failure.
    pub fn create_symlink(
        &self,
        parent_id: u64,
        name: &str,
        target: &str,
    ) -> Result<FileAttributes, i32> {
        let result = self
            .fs
            .create_symlink(parent_id, name.to_string(), target.to_string());
        if result.result_attrs_is_ok() {
            Ok(result.result_attrs_unwrap())
        } else {
            Err(result.result_attrs_error())
        }
    }

    /// Reads the target of a symbolic link.
    ///
    /// Returns `Ok(target_string)` on success, `Err(errno)` on failure.
    pub fn read_symlink(&self, item_id: u64) -> Result<String, i32> {
        let result = self.fs.read_symlink(item_id);
        if result.result_bytes_is_ok() {
            let bytes = result.result_bytes_unwrap();
            String::from_utf8(bytes).map_err(|_| libc::EILSEQ)
        } else {
            Err(result.result_bytes_error())
        }
    }

    // ========================================================================
    // Removal and Rename Operations
    // ========================================================================

    /// Removes a file, directory, or symlink.
    ///
    /// The `item_id` must match the item at `parent_id/name`.
    pub fn remove(&self, parent_id: u64, name: &str, item_id: u64) -> Result<(), i32> {
        let result = self.fs.remove(parent_id, name.to_string(), item_id);
        if result.result_unit_is_ok() {
            Ok(())
        } else {
            Err(result.result_unit_error())
        }
    }

    /// Renames or moves an item.
    ///
    /// Can rename within the same directory or move to a different directory.
    pub fn rename(
        &self,
        src_parent_id: u64,
        src_name: &str,
        dst_parent_id: u64,
        dst_name: &str,
        item_id: u64,
    ) -> Result<(), i32> {
        let result = self.fs.rename(
            src_parent_id,
            src_name.to_string(),
            dst_parent_id,
            dst_name.to_string(),
            item_id,
        );
        if result.result_unit_is_ok() {
            Ok(())
        } else {
            Err(result.result_unit_error())
        }
    }

    /// Reclaims an item ID, allowing it to be reused.
    pub fn reclaim(&self, item_id: u64) {
        self.fs.reclaim(item_id);
    }

    // ========================================================================
    // Volume Operations
    // ========================================================================

    /// Gets volume statistics.
    pub fn get_volume_stats(&self) -> Result<VolumeStatistics, i32> {
        let result = self.fs.get_volume_stats();
        if result.result_stats_is_ok() {
            Ok(result.result_stats_unwrap())
        } else {
            Err(result.result_stats_error())
        }
    }

    // ========================================================================
    // Convenience Methods
    // ========================================================================

    /// Creates a file and writes content to it in one operation.
    ///
    /// This is a convenience method that combines create_file, open_file,
    /// write_file, and close_file.
    pub fn write_new_file(&self, parent_id: u64, name: &str, content: &[u8]) -> Result<u64, i32> {
        let attrs = self.create_file(parent_id, name)?;
        let item_id = attrs.attr_item_id();

        let handle = self.open_file(item_id, true)?;
        self.write_file(handle, 0, content)?;
        self.close_file(handle)?;

        Ok(item_id)
    }

    /// Reads the entire content of a file.
    ///
    /// This is a convenience method that opens, reads, and closes the file.
    pub fn read_entire_file(&self, item_id: u64) -> Result<Vec<u8>, i32> {
        let handle = self.open_file(item_id, false)?;
        // Read up to 100MB (should be enough for any test)
        let content = self.read_file(handle, 0, 100 * 1024 * 1024)?;
        self.close_file(handle)?;
        Ok(content)
    }

    /// Lists all entries in a directory (handles pagination).
    ///
    /// Returns all directory entries, not just the first page.
    pub fn list_directory(&self, item_id: u64) -> Result<Vec<DirectoryEntry>, i32> {
        let mut all_entries = Vec::new();
        let mut cookie = 0u64;

        loop {
            let entries = self.enumerate_directory(item_id, cookie)?;
            if entries.is_empty() {
                break;
            }
            all_entries.extend(entries);

            let next_cookie = self.get_enumeration_cookie(item_id, cookie);
            if next_cookie == 0 {
                break;
            }
            cookie = next_cookie;
        }

        Ok(all_entries)
    }

    /// Checks if an item exists at the given path.
    pub fn exists(&self, parent_id: u64, name: &str) -> bool {
        self.lookup(parent_id, name).is_ok()
    }
}

impl Default for TestFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TestFilesystem {
    fn drop(&mut self) {
        // Shutdown the filesystem before the temp vault is dropped
        self.fs.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        let fs = TestFilesystem::new();
        assert_eq!(fs.root_id(), 2);
    }

    #[test]
    fn test_harness_root_enumeration() {
        let fs = TestFilesystem::new();
        let entries = fs.enumerate_directory(fs.root_id(), 0).unwrap();
        // Fresh vault should be empty
        assert!(entries.is_empty());
    }

    #[test]
    fn test_harness_volume_stats() {
        let fs = TestFilesystem::new();
        let stats = fs.get_volume_stats().unwrap();
        assert!(stats.stats_total_bytes() > 0);
        assert!(stats.stats_block_size() > 0);
    }
}
