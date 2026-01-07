//! Apple File Provider backend for Cryptomator vault mounting.
//!
//! This crate provides a [`MountBackend`] implementation using Apple's File Provider API
//! (NSFileProviderReplicatedExtension) to expose Cryptomator vaults as native macOS
//! cloud storage volumes in `~/Library/CloudStorage/`.
//!
//! ## Requirements
//!
//! - macOS 13+ (Ventura)
//! - File Provider extension enabled in System Settings

#![warn(missing_docs)]
#![warn(clippy::all)]
// swift_bridge generates code with unnecessary casts that we can't control
#![allow(clippy::unnecessary_cast)]

mod filesystem;
mod item;

/// Extension lifecycle management - installation, verification, and updates.
///
/// This module handles embedding the pre-built File Provider extension bundle,
/// installing it to the user's Application Support directory, and managing updates.
#[cfg(target_os = "macos")]
mod extension_manager;

#[cfg(target_os = "macos")]
pub use extension_manager::{ExtensionManager, ExtensionStatus, InstallError};

/// File Provider mount backend implementation.
///
/// This module provides a [`MountBackend`] implementation for Apple's File Provider API,
/// allowing vaults to appear as cloud storage volumes alongside iCloud, Google Drive, etc.
#[cfg(target_os = "macos")]
mod backend;

#[cfg(target_os = "macos")]
pub use backend::{FileProviderBackend, FileProviderMountHandle};

/// XPC client for controlling the File Provider extension.
///
/// This module provides a high-level Rust client for mounting and managing
/// Cryptomator vaults via the File Provider extension's XPC service.
#[cfg(target_os = "macos")]
pub mod xpc;

/// FSEvents watcher for detecting vault changes.
///
/// When a vault is stored on a cloud service (Google Drive, Dropbox, etc.),
/// this watcher detects changes and signals the File Provider to refresh.
#[cfg(target_os = "macos")]
pub mod watcher;

/// Automatic recovery for FileProvider domains.
///
/// This module handles periodic health checks and automatic re-registration
/// of domains that become disconnected or unhealthy.
#[cfg(target_os = "macos")]
pub mod recovery;

pub use filesystem::{
    fp_fs_new, FileProviderFilesystem, FileProviderItem, FpError, FpResultChanges,
    FpResultContents, FpResultEnumeration, FpResultFs, FpResultItem, FpResultUnit,
    FpResultWorkingSet,
};

pub use item::{decode_identifier, encode_identifier, ItemType, ROOT_ITEM_IDENTIFIER};

#[swift_bridge::bridge]
mod ffi {
    // FileProviderFilesystem - main filesystem handle
    extern "Rust" {
        type FileProviderFilesystem;

        #[swift_bridge(swift_name = "create")]
        fn fp_fs_new(vault_path: &str, password: &str) -> FpResultFs;

        fn item(&self, identifier: String) -> FpResultItem;

        #[swift_bridge(swift_name = "fetchContents")]
        fn fetch_contents(&self, identifier: String, dest_path: String) -> FpResultUnit;

        #[swift_bridge(swift_name = "createItem")]
        fn create_item(
            &self,
            parent: String,
            name: String,
            item_type: u8,
            contents: Option<String>,
        ) -> FpResultItem;

        #[swift_bridge(swift_name = "modifyItem")]
        fn modify_item(
            &self,
            identifier: String,
            new_parent: Option<String>,
            new_name: Option<String>,
            new_contents: Option<String>,
        ) -> FpResultItem;

        #[swift_bridge(swift_name = "deleteItem")]
        fn delete_item(&self, identifier: String) -> FpResultUnit;

        fn enumerate(&self, container: String, page: u32) -> FpResultEnumeration;

        #[swift_bridge(swift_name = "changesSince")]
        fn changes_since(&self, anchor: &str) -> FpResultChanges;

        #[swift_bridge(swift_name = "currentAnchor")]
        fn current_anchor(&self) -> String;

        #[swift_bridge(swift_name = "enumerateWorkingSet")]
        fn enumerate_working_set(&self) -> FpResultWorkingSet;

        #[swift_bridge(swift_name = "workingSetChangesSince")]
        fn working_set_changes_since(&self, anchor: &str) -> FpResultChanges;

        fn shutdown(&mut self);
    }

    // Result wrapper for FileProviderFilesystem creation
    extern "Rust" {
        type FpResultFs;

        #[swift_bridge(swift_name = "isOk")]
        fn result_fs_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getErrorCode")]
        fn result_fs_error_code(&self) -> i32;

        #[swift_bridge(swift_name = "getErrorDomain")]
        fn result_fs_error_domain(&self) -> String;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_fs_unwrap(self) -> FileProviderFilesystem;
    }

    // Result wrapper for FileProviderItem
    extern "Rust" {
        type FpResultItem;

        #[swift_bridge(swift_name = "isOk")]
        fn result_item_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getErrorCode")]
        fn result_item_error_code(&self) -> i32;

        #[swift_bridge(swift_name = "getErrorDomain")]
        fn result_item_error_domain(&self) -> String;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_item_unwrap(self) -> FileProviderItem;
    }

    // Result wrapper for unit operations
    extern "Rust" {
        type FpResultUnit;

        #[swift_bridge(swift_name = "isOk")]
        fn result_unit_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getErrorCode")]
        fn result_unit_error_code(&self) -> i32;

        #[swift_bridge(swift_name = "getErrorDomain")]
        fn result_unit_error_domain(&self) -> String;
    }

    // Result wrapper for file contents (URL path)
    extern "Rust" {
        type FpResultContents;

        #[swift_bridge(swift_name = "isOk")]
        fn result_contents_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getErrorCode")]
        fn result_contents_error_code(&self) -> i32;

        #[swift_bridge(swift_name = "getErrorDomain")]
        fn result_contents_error_domain(&self) -> String;

        #[swift_bridge(swift_name = "unwrap")]
        fn result_contents_unwrap(&self) -> String;
    }

    // Result wrapper for enumeration
    extern "Rust" {
        type FpResultEnumeration;

        #[swift_bridge(swift_name = "isOk")]
        fn result_enum_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getErrorCode")]
        fn result_enum_error_code(&self) -> i32;

        #[swift_bridge(swift_name = "getErrorDomain")]
        fn result_enum_error_domain(&self) -> String;

        #[swift_bridge(swift_name = "getItems")]
        fn result_enum_items(&self) -> Vec<FileProviderItem>;

        #[swift_bridge(swift_name = "hasMore")]
        fn result_enum_has_more(&self) -> bool;

        #[swift_bridge(swift_name = "getNextPage")]
        fn result_enum_next_page(&self) -> u32;
    }

    // Result wrapper for changes
    extern "Rust" {
        type FpResultChanges;

        #[swift_bridge(swift_name = "isOk")]
        fn result_changes_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getErrorCode")]
        fn result_changes_error_code(&self) -> i32;

        #[swift_bridge(swift_name = "getErrorDomain")]
        fn result_changes_error_domain(&self) -> String;

        #[swift_bridge(swift_name = "getUpdatedItems")]
        fn result_changes_updated(&self) -> Vec<FileProviderItem>;

        #[swift_bridge(swift_name = "getDeletedIdentifiers")]
        fn result_changes_deleted(&self) -> Vec<String>;

        #[swift_bridge(swift_name = "getNewAnchor")]
        fn result_changes_anchor(&self) -> String;
    }

    // Result wrapper for working set enumeration
    extern "Rust" {
        type FpResultWorkingSet;

        #[swift_bridge(swift_name = "isOk")]
        fn result_ws_is_ok(&self) -> bool;

        #[swift_bridge(swift_name = "getErrorCode")]
        fn result_ws_error_code(&self) -> i32;

        #[swift_bridge(swift_name = "getErrorDomain")]
        fn result_ws_error_domain(&self) -> String;

        #[swift_bridge(swift_name = "getItems")]
        fn result_ws_items(&self) -> Vec<FileProviderItem>;
    }

    // FileProviderItem - opaque item container
    extern "Rust" {
        type FileProviderItem;

        fn identifier(&self) -> String;

        #[swift_bridge(swift_name = "parentIdentifier")]
        fn parent_identifier(&self) -> String;

        fn filename(&self) -> Vec<u8>;

        #[swift_bridge(swift_name = "itemType")]
        fn item_type(&self) -> u8;

        fn size(&self) -> u64;

        #[swift_bridge(swift_name = "contentModificationDate")]
        fn content_modification_date(&self) -> f64;

        #[swift_bridge(swift_name = "creationDate")]
        fn creation_date(&self) -> f64;
    }

    // XPC Password Client - for secure Keychain password retrieval
    extern "Swift" {
        type XPCPasswordClient;

        #[swift_bridge(init)]
        fn new() -> XPCPasswordClient;

        fn connect(&self);

        #[swift_bridge(swift_name = "getPassword")]
        fn get_password(&self, domain_id: String) -> String;

        fn disconnect(&self);
    }
}
