//! Swift FFI bindings for Cryptomator vault FSKit integration.
//!
//! This crate provides a thin FFI layer exposing [`CryptoFilesystem`] to Swift,
//! enabling native macOS FSKit filesystem extensions without an external bridge app.
//!
//! ## Error Handling
//!
//! Error handling uses a Result-like pattern with opaque `FsResult*` types.
//! Each result type has `isOk()`, `getError()` (returns errno), and a value getter.
//!
//! ## XPC Client
//!
//! On macOS, this crate also provides an XPC client for communicating with the
//! FSKit extension from CLI or Desktop applications. See the [`xpc`] module for details.

#![warn(missing_docs)]
#![warn(clippy::all)]
// swift_bridge generates code with unnecessary casts that we can't control
#![allow(clippy::unnecessary_cast)]

mod filesystem;

/// FSKit mount backend implementation.
///
/// This module provides a `MountBackend` implementation for FSKit,
/// allowing the CLI and desktop apps to use FSKit as a mount backend.
#[cfg(target_os = "macos")]
mod backend;

#[cfg(target_os = "macos")]
pub use backend::{FskitBackend, FskitMountHandle};

/// XPC client for controlling the FSKit extension.
///
/// This module provides a high-level Rust client for mounting and managing
/// Cryptomator vaults via the FSKit extension's XPC service.
///
/// # Availability
///
/// The XPC client is only available on macOS 15.4+. Use [`FskitClient::is_available`]
/// to check before attempting to connect.
#[cfg(target_os = "macos")]
pub mod xpc;

pub use filesystem::{
    crypto_fs_new, CryptoFilesystem, DirectoryEntry, FileAttributes, FsError,
    FsResultAttrs, FsResultBytes, FsResultDirEntries, FsResultFs, FsResultHandle,
    FsResultStats, FsResultUnit, FsResultWritten, VolumeStatistics,
};

#[swift_bridge::bridge]
mod ffi {
    // CryptoFilesystem - main filesystem handle
    extern "Rust" {
        type CryptoFilesystem;

        // Factory function that returns a result wrapper
        #[swift_bridge(swift_name = "create")]
        fn crypto_fs_new(vault_path: String, password: String) -> FsResultFs;

        fn get_root_item_id(&self) -> u64;

        fn shutdown(&mut self);

        #[swift_bridge(swift_name = "getVolumeStats")]
        fn get_volume_stats(&self) -> FsResultStats;

        fn lookup(&self, parent_id: u64, name: String) -> FsResultAttrs;

        #[swift_bridge(swift_name = "getAttributes")]
        fn get_attributes(&self, item_id: u64) -> FsResultAttrs;

        #[swift_bridge(swift_name = "enumerateDirectory")]
        fn enumerate_directory(&self, item_id: u64, cookie: u64) -> FsResultDirEntries;

        #[swift_bridge(swift_name = "getEnumerationCookie")]
        fn get_enumeration_cookie(&self, item_id: u64, cookie: u64) -> u64;

        #[swift_bridge(swift_name = "openFile")]
        fn open_file(&self, item_id: u64, for_write: bool) -> FsResultHandle;

        #[swift_bridge(swift_name = "closeFile")]
        fn close_file(&self, handle: u64) -> FsResultUnit;

        #[swift_bridge(swift_name = "readFile")]
        fn read_file(&self, handle: u64, offset: i64, length: i64) -> FsResultBytes;

        #[swift_bridge(swift_name = "writeFile")]
        fn write_file(&self, handle: u64, offset: i64, data: Vec<u8>) -> FsResultWritten;

        #[swift_bridge(swift_name = "createFile")]
        fn create_file(&self, parent_id: u64, name: String) -> FsResultAttrs;

        #[swift_bridge(swift_name = "createDirectory")]
        fn create_directory(&self, parent_id: u64, name: String) -> FsResultAttrs;

        #[swift_bridge(swift_name = "createSymlink")]
        fn create_symlink(&self, parent_id: u64, name: String, target: String) -> FsResultAttrs;

        fn remove(&self, parent_id: u64, name: String, item_id: u64) -> FsResultUnit;

        fn rename(
            &self,
            src_parent_id: u64,
            src_name: String,
            dst_parent_id: u64,
            dst_name: String,
            item_id: u64,
        ) -> FsResultUnit;

        #[swift_bridge(swift_name = "readSymlink")]
        fn read_symlink(&self, item_id: u64) -> FsResultBytes;

        fn truncate(&self, item_id: u64, size: u64) -> FsResultUnit;

        fn reclaim(&self, item_id: u64);
    }

    // Result wrapper for CryptoFilesystem creation
    extern "Rust" {
        type FsResultFs;

        #[swift_bridge(swift_name = "isOk")]
        fn result_fs_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_fs_error(&self) -> i32;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_fs_unwrap(self) -> CryptoFilesystem;
    }

    // Result wrapper for FileAttributes
    extern "Rust" {
        type FsResultAttrs;

        #[swift_bridge(swift_name = "isOk")]
        fn result_attrs_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_attrs_error(&self) -> i32;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_attrs_unwrap(self) -> FileAttributes;
    }

    // Result wrapper for VolumeStatistics
    extern "Rust" {
        type FsResultStats;

        #[swift_bridge(swift_name = "isOk")]
        fn result_stats_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_stats_error(&self) -> i32;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_stats_unwrap(self) -> VolumeStatistics;
    }

    // Result wrapper for Vec<DirectoryEntry>
    extern "Rust" {
        type FsResultDirEntries;

        #[swift_bridge(swift_name = "isOk")]
        fn result_dir_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_dir_error(&self) -> i32;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_dir_unwrap(self) -> Vec<DirectoryEntry>;
    }

    // Result wrapper for file handles (u64)
    extern "Rust" {
        type FsResultHandle;

        #[swift_bridge(swift_name = "isOk")]
        fn result_handle_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_handle_error(&self) -> i32;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_handle_unwrap(&self) -> u64;
    }

    // Result wrapper for unit (void) operations
    extern "Rust" {
        type FsResultUnit;

        #[swift_bridge(swift_name = "isOk")]
        fn result_unit_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_unit_error(&self) -> i32;
    }

    // Result wrapper for byte data
    extern "Rust" {
        type FsResultBytes;

        #[swift_bridge(swift_name = "isOk")]
        fn result_bytes_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_bytes_error(&self) -> i32;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_bytes_unwrap(self) -> Vec<u8>;
    }

    // Result wrapper for bytes written (i64)
    extern "Rust" {
        type FsResultWritten;

        #[swift_bridge(swift_name = "isOk")]
        fn result_written_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getError")]
        fn result_written_error(&self) -> i32;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_written_unwrap(&self) -> i64;
    }

    // FileAttributes - opaque file attribute container
    extern "Rust" {
        type FileAttributes;

        #[swift_bridge(swift_name = "getItemId")]
        fn attr_item_id(&self) -> u64;

        #[swift_bridge(swift_name = "isDirectory")]
        fn attr_is_directory(&self) -> bool;

        #[swift_bridge(swift_name = "isFile")]
        fn attr_is_file(&self) -> bool;

        #[swift_bridge(swift_name = "isSymlink")]
        fn attr_is_symlink(&self) -> bool;

        #[swift_bridge(swift_name = "getSize")]
        fn attr_size(&self) -> u64;

        #[swift_bridge(swift_name = "getMode")]
        fn attr_mode(&self) -> u32;

        #[swift_bridge(swift_name = "getUid")]
        fn attr_uid(&self) -> u32;

        #[swift_bridge(swift_name = "getGid")]
        fn attr_gid(&self) -> u32;
    }

    // DirectoryEntry - opaque directory entry container
    extern "Rust" {
        type DirectoryEntry;

        #[swift_bridge(swift_name = "getName")]
        fn entry_name(&self) -> Vec<u8>;

        #[swift_bridge(swift_name = "getItemId")]
        fn entry_item_id(&self) -> u64;

        #[swift_bridge(swift_name = "isDirectory")]
        fn entry_is_directory(&self) -> bool;

        #[swift_bridge(swift_name = "isFile")]
        fn entry_is_file(&self) -> bool;

        #[swift_bridge(swift_name = "isSymlink")]
        fn entry_is_symlink(&self) -> bool;

        #[swift_bridge(swift_name = "getSize")]
        fn entry_size(&self) -> u64;
    }

    // VolumeStatistics - opaque volume stats container
    extern "Rust" {
        type VolumeStatistics;

        #[swift_bridge(swift_name = "getTotalBytes")]
        fn stats_total_bytes(&self) -> u64;

        #[swift_bridge(swift_name = "getAvailableBytes")]
        fn stats_available_bytes(&self) -> u64;

        #[swift_bridge(swift_name = "getUsedBytes")]
        fn stats_used_bytes(&self) -> u64;

        #[swift_bridge(swift_name = "getTotalInodes")]
        fn stats_total_inodes(&self) -> u64;

        #[swift_bridge(swift_name = "getAvailableInodes")]
        fn stats_available_inodes(&self) -> u64;

        #[swift_bridge(swift_name = "getBlockSize")]
        fn stats_block_size(&self) -> u32;
    }
}
