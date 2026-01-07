//! Core filesystem implementation for File Provider.
//!
//! This module provides [`FileProviderFilesystem`], the main Rust type that handles
//! all filesystem operations for the File Provider extension.

use crate::item::{
    decode_identifier, encode_identifier, filename_from_path, parent_identifier, ItemType,
    ROOT_ITEM_IDENTIFIER, TRASH_IDENTIFIER, WORKING_SET_IDENTIFIER,
};
use oxcrypt_core::error::{VaultOperationError, VaultWriteError};
use oxcrypt_core::fs::encrypted_to_plaintext_size_or_zero;
use oxcrypt_core::vault::config::VaultError;
use oxcrypt_core::vault::operations::DirEntry;
use oxcrypt_core::vault::path::VaultPath;
use oxcrypt_core::vault::VaultOperationsAsync;
use oxcrypt_mount::moka_cache::SyncTtlCache;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::runtime::Runtime;
use tracing::{debug, error, trace};

/// Default page size for enumeration (number of items per page).
const ENUMERATION_PAGE_SIZE: usize = 100;

// ============================================================================
// Error Type
// ============================================================================

/// Error type for File Provider operations.
#[derive(Debug, Clone, Error)]
pub enum FpError {
    /// Item not found
    #[error("item not found: {0}")]
    NotFound(String),

    /// Item already exists
    #[error("item already exists: {0}")]
    AlreadyExists(String),

    /// Permission denied
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid argument
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// Not a directory
    #[error("not a directory: {0}")]
    NotDirectory(String),

    /// Directory not empty
    #[error("directory not empty: {0}")]
    NotEmpty(String),

    /// Vault error
    #[error("vault error: {0}")]
    VaultError(String),

    /// Not authenticated
    #[error("not authenticated")]
    NotAuthenticated,
}

impl FpError {
    /// Get the errno-like error code for this error.
    pub fn error_code(&self) -> i32 {
        match self {
            FpError::NotFound(_) => libc::ENOENT,
            FpError::AlreadyExists(_) => libc::EEXIST,
            FpError::PermissionDenied(_) | FpError::NotAuthenticated => libc::EACCES,
            FpError::InvalidArgument(_) => libc::EINVAL,
            FpError::IoError(_) | FpError::VaultError(_) => libc::EIO,
            FpError::NotDirectory(_) => libc::ENOTDIR,
            FpError::NotEmpty(_) => libc::ENOTEMPTY,
        }
    }

    /// Get the NSFileProviderError domain string for this error.
    pub fn error_domain(&self) -> &'static str {
        match self {
            FpError::NotFound(_) | FpError::NotDirectory(_) => "NSFileProviderErrorNoSuchItem",
            FpError::AlreadyExists(_) => "NSFileProviderErrorFilenameCollision",
            FpError::PermissionDenied(_) | FpError::NotAuthenticated => {
                "NSFileProviderErrorNotAuthenticated"
            }
            FpError::InvalidArgument(_) => "NSFileProviderErrorPageExpired",
            FpError::IoError(_) | FpError::VaultError(_) => "NSFileProviderErrorServerUnreachable",
            FpError::NotEmpty(_) => "NSFileProviderErrorDirectoryNotEmpty",
        }
    }

    /// Maps a string error message to the appropriate FpError.
    fn from_message(msg: &str) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("not found") || lower.contains("no such") {
            FpError::NotFound(msg.to_string())
        } else if lower.contains("already exists") || lower.contains("exists") {
            FpError::AlreadyExists(msg.to_string())
        } else if lower.contains("not empty") {
            FpError::NotEmpty(msg.to_string())
        } else if lower.contains("is a directory") || lower.contains("not a directory") {
            FpError::NotDirectory(msg.to_string())
        } else if lower.contains("permission") || lower.contains("access denied") {
            FpError::PermissionDenied(msg.to_string())
        } else if lower.contains("invalid") {
            FpError::InvalidArgument(msg.to_string())
        } else {
            FpError::IoError(msg.to_string())
        }
    }
}

impl From<VaultOperationError> for FpError {
    fn from(e: VaultOperationError) -> Self {
        match &e {
            VaultOperationError::PathNotFound { path } => FpError::NotFound(path.clone()),
            VaultOperationError::FileNotFound { filename, .. } => {
                FpError::NotFound(filename.clone())
            }
            VaultOperationError::DirectoryNotFound { name, .. }
            | VaultOperationError::SymlinkNotFound { name, .. } => FpError::NotFound(name.clone()),
            VaultOperationError::NotAFile { path, .. } => {
                FpError::NotDirectory(format!("not a file: {path}"))
            }
            VaultOperationError::NotADirectory { path, .. } => {
                FpError::NotDirectory(format!("not a directory: {path}"))
            }
            VaultOperationError::NotASymlink { path, .. } => {
                FpError::InvalidArgument(format!("not a symlink: {path}"))
            }
            VaultOperationError::EmptyPath => FpError::InvalidArgument("empty path".to_string()),
            _ => {
                let msg = e.to_string();
                FpError::from_message(&msg)
            }
        }
    }
}

impl From<VaultWriteError> for FpError {
    fn from(e: VaultWriteError) -> Self {
        match &e {
            VaultWriteError::FileNotFound { filename, .. } => FpError::NotFound(filename.clone()),
            VaultWriteError::DirectoryNotFound { name, .. } => FpError::NotFound(name.clone()),
            VaultWriteError::FileAlreadyExists { filename, .. } => {
                FpError::AlreadyExists(filename.clone())
            }
            VaultWriteError::DirectoryAlreadyExists { name, .. }
            | VaultWriteError::SymlinkAlreadyExists { name, .. } => {
                FpError::AlreadyExists(name.clone())
            }
            VaultWriteError::PathExists { path, .. } => FpError::AlreadyExists(path.clone()),
            VaultWriteError::DirectoryNotEmpty { context, .. } => {
                FpError::NotEmpty(context.to_string())
            }
            _ => {
                let msg = e.to_string();
                FpError::from_message(&msg)
            }
        }
    }
}

impl From<std::io::Error> for FpError {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::NotFound => FpError::NotFound(e.to_string()),
            ErrorKind::AlreadyExists => FpError::AlreadyExists(e.to_string()),
            ErrorKind::PermissionDenied => FpError::PermissionDenied(e.to_string()),
            ErrorKind::InvalidInput | ErrorKind::InvalidData => {
                FpError::InvalidArgument(e.to_string())
            }
            _ => FpError::IoError(e.to_string()),
        }
    }
}

impl From<VaultError> for FpError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Io(io_err) => FpError::from(io_err),
            _ => {
                // MasterKeyExtraction, ClaimValidation, KeyClone errors
                // are all configuration/auth errors
                FpError::NotAuthenticated
            }
        }
    }
}

impl From<crate::item::ItemIdError> for FpError {
    fn from(e: crate::item::ItemIdError) -> Self {
        FpError::InvalidArgument(e.to_string())
    }
}

// ============================================================================
// File Provider Item
// ============================================================================

/// A File Provider item with all necessary attributes.
pub struct FileProviderItem {
    identifier: String,
    parent_id: String,
    filename: String,
    item_type: ItemType,
    size: u64,
    content_modification_date: f64,
    creation_date: f64,
}

impl FileProviderItem {
    /// Create a new item.
    pub fn new(
        vault_path: &str,
        item_type: ItemType,
        size: u64,
        mtime: f64,
        ctime: f64,
    ) -> Self {
        Self {
            identifier: encode_identifier(vault_path),
            parent_id: parent_identifier(vault_path),
            filename: filename_from_path(vault_path),
            item_type,
            size,
            content_modification_date: mtime,
            creation_date: ctime,
        }
    }

    /// Create root item.
    fn root() -> Self {
        Self {
            identifier: ROOT_ITEM_IDENTIFIER.to_string(),
            parent_id: ROOT_ITEM_IDENTIFIER.to_string(),
            filename: String::new(),
            item_type: ItemType::Directory,
            size: 0,
            content_modification_date: 0.0,
            creation_date: 0.0,
        }
    }

    /// Get the item identifier.
    pub fn identifier(&self) -> String {
        self.identifier.clone()
    }

    /// Get the parent identifier.
    pub fn parent_identifier(&self) -> String {
        self.parent_id.clone()
    }

    /// Get the filename as UTF-8 bytes.
    pub fn filename(&self) -> Vec<u8> {
        self.filename.as_bytes().to_vec()
    }

    /// Get the item type.
    pub fn item_type(&self) -> u8 {
        self.item_type.into()
    }

    /// Get the file size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the content modification date as Unix timestamp.
    pub fn content_modification_date(&self) -> f64 {
        self.content_modification_date
    }

    /// Get the creation date as Unix timestamp.
    pub fn creation_date(&self) -> f64 {
        self.creation_date
    }
}

// ============================================================================
// Result Wrapper Types for FFI
// ============================================================================

/// Result wrapper for FileProviderFilesystem creation.
pub struct FpResultFs {
    result: Result<FileProviderFilesystem, FpError>,
}

impl FpResultFs {
    /// Check if the result is Ok.
    pub fn result_fs_is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the error code (0 if Ok).
    pub fn result_fs_error_code(&self) -> i32 {
        self.result.as_ref().err().map_or(0, FpError::error_code)
    }

    /// Get the error domain string.
    pub fn result_fs_error_domain(&self) -> String {
        self.result
            .as_ref()
            .err()
            .map_or(String::new(), |e| e.error_domain().to_string())
    }

    /// Unwrap the filesystem (panics if error).
    ///
    /// # Panics
    /// Panics if `result_fs_is_ok()` returns false. Always check `is_ok()` before calling.
    pub fn result_fs_unwrap(self) -> FileProviderFilesystem {
        self.result
            .expect("FFI error: called result_fs_unwrap without checking result_fs_is_ok first")
    }
}

/// Result wrapper for FileProviderItem.
pub struct FpResultItem {
    result: Result<FileProviderItem, FpError>,
}

impl FpResultItem {
    /// Check if the result is Ok.
    pub fn result_item_is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the error code (0 if Ok).
    pub fn result_item_error_code(&self) -> i32 {
        self.result.as_ref().err().map_or(0, FpError::error_code)
    }

    /// Get the error domain string.
    pub fn result_item_error_domain(&self) -> String {
        self.result
            .as_ref()
            .err()
            .map_or(String::new(), |e| e.error_domain().to_string())
    }

    /// Unwrap the item (panics if error).
    ///
    /// # Panics
    /// Panics if `result_item_is_ok()` returns false. Always check `is_ok()` before calling.
    pub fn result_item_unwrap(self) -> FileProviderItem {
        self.result
            .expect("FFI error: called result_item_unwrap without checking result_item_is_ok first")
    }
}

/// Result wrapper for unit operations.
pub struct FpResultUnit {
    result: Result<(), FpError>,
}

impl FpResultUnit {
    /// Check if the result is Ok.
    pub fn result_unit_is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the error code (0 if Ok).
    pub fn result_unit_error_code(&self) -> i32 {
        self.result.as_ref().err().map_or(0, FpError::error_code)
    }

    /// Get the error domain string.
    pub fn result_unit_error_domain(&self) -> String {
        self.result
            .as_ref()
            .err()
            .map_or(String::new(), |e| e.error_domain().to_string())
    }
}

/// Result wrapper for file contents operations.
pub struct FpResultContents {
    result: Result<String, FpError>,
}

impl FpResultContents {
    /// Check if the result is Ok.
    pub fn result_contents_is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the error code (0 if Ok).
    pub fn result_contents_error_code(&self) -> i32 {
        self.result.as_ref().err().map_or(0, FpError::error_code)
    }

    /// Get the error domain string.
    pub fn result_contents_error_domain(&self) -> String {
        self.result
            .as_ref()
            .err()
            .map_or(String::new(), |e| e.error_domain().to_string())
    }

    /// Unwrap the contents (panics if error).
    ///
    /// # Panics
    /// Panics if `result_contents_is_ok()` returns false. Always check `is_ok()` before calling.
    pub fn result_contents_unwrap(&self) -> String {
        self.result.clone().expect(
            "FFI error: called result_contents_unwrap without checking result_contents_is_ok first",
        )
    }
}

/// Result wrapper for enumeration operations.
pub struct FpResultEnumeration {
    result: Result<EnumerationResult, FpError>,
}

struct EnumerationResult {
    items: Vec<FileProviderItem>,
    has_more: bool,
    next_page: u32,
}

impl FpResultEnumeration {
    /// Check if the result is Ok.
    pub fn result_enum_is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the error code (0 if Ok).
    pub fn result_enum_error_code(&self) -> i32 {
        self.result.as_ref().err().map_or(0, FpError::error_code)
    }

    /// Get the error domain string.
    pub fn result_enum_error_domain(&self) -> String {
        self.result
            .as_ref()
            .err()
            .map_or(String::new(), |e| e.error_domain().to_string())
    }

    /// Get the enumerated items (empty if error).
    pub fn result_enum_items(&self) -> Vec<FileProviderItem> {
        self.result.as_ref().ok().map_or(Vec::new(), |r| {
            // Clone items for Swift - in production we'd use a better approach
            r.items
                .iter()
                .map(|i| FileProviderItem {
                    identifier: i.identifier.clone(),
                    parent_id: i.parent_id.clone(),
                    filename: i.filename.clone(),
                    item_type: i.item_type,
                    size: i.size,
                    content_modification_date: i.content_modification_date,
                    creation_date: i.creation_date,
                })
                .collect()
        })
    }

    /// Check if there are more items to enumerate.
    pub fn result_enum_has_more(&self) -> bool {
        self.result.as_ref().ok().is_some_and(|r| r.has_more)
    }

    /// Get the next page number (0 if no more).
    pub fn result_enum_next_page(&self) -> u32 {
        self.result.as_ref().ok().map_or(0, |r| r.next_page)
    }
}

/// Result wrapper for changes operations.
pub struct FpResultChanges {
    result: Result<ChangesResult, FpError>,
}

struct ChangesResult {
    updated: Vec<FileProviderItem>,
    deleted: Vec<String>,
    anchor: String,
}

impl FpResultChanges {
    /// Check if the result is Ok.
    pub fn result_changes_is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the error code (0 if Ok).
    pub fn result_changes_error_code(&self) -> i32 {
        self.result.as_ref().err().map_or(0, FpError::error_code)
    }

    /// Get the error domain string.
    pub fn result_changes_error_domain(&self) -> String {
        self.result
            .as_ref()
            .err()
            .map_or(String::new(), |e| e.error_domain().to_string())
    }

    /// Get the list of updated items (empty if error).
    pub fn result_changes_updated(&self) -> Vec<FileProviderItem> {
        self.result.as_ref().ok().map_or(Vec::new(), |r| {
            r.updated
                .iter()
                .map(|i| FileProviderItem {
                    identifier: i.identifier.clone(),
                    parent_id: i.parent_id.clone(),
                    filename: i.filename.clone(),
                    item_type: i.item_type,
                    size: i.size,
                    content_modification_date: i.content_modification_date,
                    creation_date: i.creation_date,
                })
                .collect()
        })
    }

    /// Get the list of deleted item identifiers (empty if error).
    pub fn result_changes_deleted(&self) -> Vec<String> {
        self.result
            .as_ref()
            .ok()
            .map_or(Vec::new(), |r| r.deleted.clone())
    }

    /// Get the new sync anchor string (empty if error).
    pub fn result_changes_anchor(&self) -> String {
        self.result
            .as_ref()
            .ok()
            .map_or(String::new(), |r| r.anchor.clone())
    }
}

/// Result wrapper for working set enumeration.
pub struct FpResultWorkingSet {
    result: Result<Vec<FileProviderItem>, FpError>,
}

impl FpResultWorkingSet {
    /// Check if the result is Ok.
    pub fn result_ws_is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the error code (0 if Ok).
    pub fn result_ws_error_code(&self) -> i32 {
        self.result.as_ref().err().map_or(0, FpError::error_code)
    }

    /// Get the error domain string.
    pub fn result_ws_error_domain(&self) -> String {
        self.result
            .as_ref()
            .err()
            .map_or(String::new(), |e| e.error_domain().to_string())
    }

    /// Get the working set items (empty if error).
    pub fn result_ws_items(&self) -> Vec<FileProviderItem> {
        self.result.as_ref().ok().map_or(Vec::new(), |items| {
            items
                .iter()
                .map(|i| FileProviderItem {
                    identifier: i.identifier.clone(),
                    parent_id: i.parent_id.clone(),
                    filename: i.filename.clone(),
                    item_type: i.item_type,
                    size: i.size,
                    content_modification_date: i.content_modification_date,
                    creation_date: i.creation_date,
                })
                .collect()
        })
    }
}

// ============================================================================
// Cached Item Attributes
// ============================================================================

/// Cached item attributes for performance.
#[derive(Clone)]
struct CachedItem {
    item_type: ItemType,
    size: u64,
}

// ============================================================================
// Main Filesystem
// ============================================================================

/// Main filesystem handle for File Provider operations.
///
/// This struct wraps the vault operations and provides the interface
/// used by the Swift extension via FFI.
pub struct FileProviderFilesystem {
    /// Tokio runtime for async operations.
    runtime: Arc<Runtime>,
    /// Async vault operations (thread-safe).
    ops: Arc<VaultOperationsAsync>,
    /// Attribute cache for performance (keyed by vault path).
    attr_cache: SyncTtlCache<String, CachedItem>,
    /// Sync anchor for change tracking.
    sync_anchor: AtomicU64,
}

impl FileProviderFilesystem {
    /// Get an item by identifier.
    ///
    /// The identifier is a base64url-encoded vault path.
    /// This is the FFI-compatible method that accepts owned String for Swift bridge.
    // FFI methods must use owned String for swift_bridge compatibility
    #[allow(clippy::needless_pass_by_value)]
    pub fn item(&self, identifier: String) -> FpResultItem {
        debug!("item: {}", identifier);
        FpResultItem {
            result: self.item_internal(&identifier),
        }
    }

    fn item_internal(&self, identifier: &str) -> Result<FileProviderItem, FpError> {
        // Handle root item specially
        if identifier == ROOT_ITEM_IDENTIFIER {
            return Ok(FileProviderItem::root());
        }

        // Trash container - we don't support trash, return not found
        if identifier == TRASH_IDENTIFIER {
            return Err(FpError::NotFound(".trash".to_string()));
        }

        // Working set - treat as root for item() purposes
        if identifier == WORKING_SET_IDENTIFIER {
            return Ok(FileProviderItem::root());
        }

        // Decode identifier to vault path
        let vault_path = decode_identifier(identifier)?;
        trace!("item_internal: decoded {} -> {}", identifier, vault_path);

        // Create VaultPath
        let vpath = VaultPath::new(&vault_path);

        // Try to get from cache first
        if let Some(cached) = self.attr_cache.get(&vault_path) {
            trace!("item_internal: cache hit for {}", vault_path);
            return Ok(FileProviderItem::new(
                &vault_path,
                cached.value.item_type,
                cached.value.size,
                0.0, // mtime - we don't cache timestamps
                0.0, // ctime
            ));
        }

        // Look up the entry in the vault
        let ops = Arc::clone(&self.ops);
        let vpath_str = vpath.as_str().to_string();

        let entry: Option<DirEntry> = self
            .runtime
            .block_on(async move { ops.get_entry(&vpath_str).await });

        let entry = entry.ok_or_else(|| FpError::NotFound(vault_path.clone()))?;

        // Convert DirEntry to FileProviderItem
        let (item_type, size) = match &entry {
            DirEntry::File(info) => {
                let plaintext_size = encrypted_to_plaintext_size_or_zero(info.encrypted_size);
                (ItemType::File, plaintext_size)
            }
            DirEntry::Directory(_) => (ItemType::Directory, 0),
            DirEntry::Symlink(_) => (ItemType::Symlink, 0),
        };

        // Cache the result
        self.attr_cache.insert(
            vault_path.clone(),
            CachedItem { item_type, size },
        );

        Ok(FileProviderItem::new(&vault_path, item_type, size, 0.0, 0.0))
    }

    /// Fetch file contents to a destination path.
    ///
    /// This decrypts the file and writes it to `dest_path` for File Provider to use.
    // FFI methods must use owned String for swift_bridge compatibility
    #[allow(clippy::needless_pass_by_value)]
    pub fn fetch_contents(&self, identifier: String, dest_path: String) -> FpResultUnit {
        debug!("fetch_contents: {} -> {}", identifier, dest_path);
        FpResultUnit {
            result: self.fetch_contents_internal(&identifier, &dest_path),
        }
    }

    fn fetch_contents_internal(
        &self,
        identifier: &str,
        dest_path: &str,
    ) -> Result<(), FpError> {
        // Decode identifier to vault path
        let vault_path = decode_identifier(identifier)?;
        let vpath = VaultPath::new(&vault_path);

        // Read the file contents
        let ops = Arc::clone(&self.ops);
        let vpath_str = vpath.as_str().to_string();

        let decrypted = self
            .runtime
            .block_on(async move { ops.read_by_path(&vpath_str).await })
            .map_err(FpError::from)?;

        // Write to destination
        std::fs::write(dest_path, &decrypted.content)?;

        trace!(
            "fetch_contents: wrote {} bytes to {}",
            decrypted.content.len(),
            dest_path
        );

        Ok(())
    }

    /// Create a new item.
    ///
    /// - `parent`: Parent directory identifier
    /// - `name`: Name for the new item
    /// - `item_type`: 0=file, 1=directory, 2=symlink
    /// - `contents`: For files, path to content file; for symlinks, target path
    // FFI methods must use owned String for swift_bridge compatibility
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_item(
        &self,
        parent: String,
        name: String,
        item_type: u8,
        contents: Option<String>,
    ) -> FpResultItem {
        debug!(
            "create_item: {} / {} (type={})",
            parent, name, item_type
        );
        FpResultItem {
            result: self.create_item_internal(&parent, &name, item_type, contents.as_deref()),
        }
    }

    fn create_item_internal(
        &self,
        parent_id: &str,
        name: &str,
        item_type: u8,
        contents: Option<&str>,
    ) -> Result<FileProviderItem, FpError> {
        // Decode parent identifier to vault path
        let parent_path = if parent_id == ROOT_ITEM_IDENTIFIER {
            "/".to_string()
        } else {
            decode_identifier(parent_id)?
        };

        // Compute child path
        let child_path = if parent_path == "/" {
            format!("/{name}")
        } else {
            format!("{parent_path}/{name}")
        };

        let item_type_enum = ItemType::from(item_type);
        let ops = Arc::clone(&self.ops);

        match item_type_enum {
            ItemType::File => {
                // Read content from the provided path if given
                let content = if let Some(content_path) = contents {
                    std::fs::read(content_path)?
                } else {
                    Vec::new()
                };

                // Resolve parent to get DirId
                let child_path_clone = child_path.clone();
                let content_clone = content.clone();

                self.runtime
                    .block_on(async move {
                        let (parent_dir_id, filename) =
                            ops.resolve_parent_path(&child_path_clone).await?;
                        ops.write_file(&parent_dir_id, &filename, &content_clone)
                            .await
                    })
                    .map_err(FpError::from)?;

                // Invalidate parent cache
                self.attr_cache.invalidate(&parent_path);

                Ok(FileProviderItem::new(
                    &child_path,
                    ItemType::File,
                    content.len() as u64,
                    0.0,
                    0.0,
                ))
            }
            ItemType::Directory => {
                let child_path_clone = child_path.clone();

                self.runtime
                    .block_on(async move {
                        let (parent_dir_id, dir_name) =
                            ops.resolve_parent_path(&child_path_clone).await?;
                        ops.create_directory(&parent_dir_id, &dir_name).await
                    })
                    .map_err(FpError::from)?;

                // Invalidate parent cache
                self.attr_cache.invalidate(&parent_path);

                Ok(FileProviderItem::new(
                    &child_path,
                    ItemType::Directory,
                    0,
                    0.0,
                    0.0,
                ))
            }
            ItemType::Symlink => {
                let target = contents.ok_or_else(|| {
                    FpError::InvalidArgument("symlink requires target path".to_string())
                })?;

                let child_path_clone = child_path.clone();
                let target_clone = target.to_string();

                self.runtime
                    .block_on(async move {
                        let (parent_dir_id, link_name) =
                            ops.resolve_parent_path(&child_path_clone).await?;
                        ops.create_symlink(&parent_dir_id, &link_name, &target_clone)
                            .await
                    })
                    .map_err(FpError::from)?;

                // Invalidate parent cache
                self.attr_cache.invalidate(&parent_path);

                Ok(FileProviderItem::new(
                    &child_path,
                    ItemType::Symlink,
                    0,
                    0.0,
                    0.0,
                ))
            }
        }
    }

    /// Modify an existing item.
    ///
    /// - `identifier`: Item to modify
    /// - `new_parent`: New parent directory (for move)
    /// - `new_name`: New name (for rename)
    /// - `new_contents`: Path to new content file (for update)
    // FFI methods must use owned String for swift_bridge compatibility
    #[allow(clippy::needless_pass_by_value)]
    pub fn modify_item(
        &self,
        identifier: String,
        new_parent: Option<String>,
        new_name: Option<String>,
        new_contents: Option<String>,
    ) -> FpResultItem {
        debug!("modify_item: {}", identifier);
        FpResultItem {
            result: self.modify_item_internal(
                &identifier,
                new_parent.as_deref(),
                new_name.as_deref(),
                new_contents.as_deref(),
            ),
        }
    }

    fn modify_item_internal(
        &self,
        identifier: &str,
        new_parent: Option<&str>,
        new_name: Option<&str>,
        new_contents: Option<&str>,
    ) -> Result<FileProviderItem, FpError> {
        // Decode identifier to vault path
        let vault_path = decode_identifier(identifier)?;
        let vpath = VaultPath::new(&vault_path);

        // Get current item info
        let ops = Arc::clone(&self.ops);
        let vpath_str = vpath.as_str().to_string();

        let entry: Option<DirEntry> = self
            .runtime
            .block_on(async move { ops.get_entry(&vpath_str).await });

        let entry = entry.ok_or_else(|| FpError::NotFound(vault_path.clone()))?;

        let item_type = match &entry {
            DirEntry::File(_) => ItemType::File,
            DirEntry::Directory(_) => ItemType::Directory,
            DirEntry::Symlink(_) => ItemType::Symlink,
        };

        // Handle content update for files
        if let Some(content_path) = new_contents {
            if item_type != ItemType::File {
                return Err(FpError::InvalidArgument(
                    "cannot update contents of non-file".to_string(),
                ));
            }

            let content = std::fs::read(content_path)?;
            let ops = Arc::clone(&self.ops);
            let vpath_str = vpath.as_str().to_string();

            self.runtime
                .block_on(async move { ops.write_by_path(&vpath_str, &content).await })
                .map_err(FpError::from)?;

            // Invalidate cache
            self.attr_cache.invalidate(&vault_path);
        }

        // Handle rename/move
        let final_path = if new_parent.is_some() || new_name.is_some() {
            let current_filename = filename_from_path(&vault_path);
            let current_parent_id = parent_identifier(&vault_path);

            let new_parent_path = if let Some(parent_id) = new_parent {
                if parent_id == ROOT_ITEM_IDENTIFIER {
                    "/".to_string()
                } else {
                    decode_identifier(parent_id)?
                }
            } else {
                // Use current parent
                if current_parent_id == ROOT_ITEM_IDENTIFIER {
                    "/".to_string()
                } else {
                    decode_identifier(&current_parent_id)?
                }
            };

            let final_name = new_name.unwrap_or(&current_filename);

            let new_path = if new_parent_path == "/" {
                format!("/{final_name}")
            } else {
                format!("{new_parent_path}/{final_name}")
            };

            // Perform rename/move using the appropriate method based on type
            let ops = Arc::clone(&self.ops);
            let vault_path_clone = vault_path.clone();
            let new_name_clone = final_name.to_string();

            match item_type {
                ItemType::File => {
                    self.runtime
                        .block_on(async move {
                            let (dir_id, old_name) =
                                ops.resolve_parent_path(&vault_path_clone).await?;
                            ops.rename_file(&dir_id, &old_name, &new_name_clone).await
                        })
                        .map_err(FpError::from)?;
                }
                ItemType::Directory => {
                    self.runtime
                        .block_on(async move {
                            let (dir_id, old_name) =
                                ops.resolve_parent_path(&vault_path_clone).await?;
                            ops.rename_directory(&dir_id, &old_name, &new_name_clone)
                                .await
                        })
                        .map_err(FpError::from)?;
                }
                ItemType::Symlink => {
                    self.runtime
                        .block_on(async move {
                            let (dir_id, old_name) =
                                ops.resolve_parent_path(&vault_path_clone).await?;
                            ops.rename_symlink(&dir_id, &old_name, &new_name_clone)
                                .await
                        })
                        .map_err(FpError::from)?;
                }
            }

            // Invalidate caches
            self.attr_cache.invalidate(&vault_path);
            self.attr_cache.invalidate(&new_parent_path);

            new_path
        } else {
            vault_path.clone()
        };

        // Get updated size for files
        let size = if item_type == ItemType::File {
            let ops = Arc::clone(&self.ops);
            let final_path_str = final_path.clone();

            if let Some(DirEntry::File(info)) = self
                .runtime
                .block_on(async move { ops.get_entry(&final_path_str).await })
            {
                encrypted_to_plaintext_size_or_zero(info.encrypted_size)
            } else {
                0
            }
        } else {
            0
        };

        Ok(FileProviderItem::new(&final_path, item_type, size, 0.0, 0.0))
    }

    /// Delete an item.
    // FFI methods must use owned String for swift_bridge compatibility
    #[allow(clippy::needless_pass_by_value)]
    pub fn delete_item(&self, identifier: String) -> FpResultUnit {
        debug!("delete_item: {}", identifier);
        FpResultUnit {
            result: self.delete_item_internal(&identifier),
        }
    }

    fn delete_item_internal(&self, identifier: &str) -> Result<(), FpError> {
        // Decode identifier to vault path
        let vault_path = decode_identifier(identifier)?;
        let vpath = VaultPath::new(&vault_path);

        // Get item type to determine delete method
        let ops = Arc::clone(&self.ops);
        let vpath_str = vpath.as_str().to_string();

        let entry: Option<DirEntry> = self
            .runtime
            .block_on(async move { ops.get_entry(&vpath_str).await });

        let entry = entry.ok_or_else(|| FpError::NotFound(vault_path.clone()))?;

        // Delete based on type
        let ops = Arc::clone(&self.ops);
        let vault_path_clone = vault_path.clone();

        match entry {
            DirEntry::File(_) => {
                self.runtime
                    .block_on(async move {
                        let (dir_id, filename) = ops.resolve_parent_path(&vault_path_clone).await?;
                        ops.delete_file(&dir_id, &filename).await
                    })
                    .map_err(FpError::from)?;
            }
            DirEntry::Directory(_) => {
                self.runtime
                    .block_on(async move {
                        let (dir_id, dir_name) = ops.resolve_parent_path(&vault_path_clone).await?;
                        ops.delete_directory(&dir_id, &dir_name).await
                    })
                    .map_err(FpError::from)?;
            }
            DirEntry::Symlink(_) => {
                self.runtime
                    .block_on(async move { ops.delete_symlink_by_path(&vault_path_clone).await })
                    .map_err(FpError::from)?;
            }
        }

        // Invalidate cache
        self.attr_cache.invalidate(&vault_path);

        // Invalidate parent cache
        let parent_path = parent_identifier(&vault_path);
        if parent_path != ROOT_ITEM_IDENTIFIER
            && let Ok(parent_decoded) = decode_identifier(&parent_path) {
                self.attr_cache.invalidate(&parent_decoded);
            }

        Ok(())
    }

    /// Enumerate directory contents with pagination.
    ///
    /// - `container`: Directory identifier to enumerate
    /// - `page`: Page number (0-indexed)
    // FFI methods must use owned String for swift_bridge compatibility
    #[allow(clippy::needless_pass_by_value)]
    pub fn enumerate(&self, container: String, page: u32) -> FpResultEnumeration {
        debug!("enumerate: {} (page={})", container, page);
        FpResultEnumeration {
            result: self.enumerate_internal(&container, page),
        }
    }

    fn enumerate_internal(
        &self,
        container_id: &str,
        page: u32,
    ) -> Result<EnumerationResult, FpError> {
        // Trash container - we don't support trash, return empty list
        if container_id == TRASH_IDENTIFIER {
            return Ok(EnumerationResult {
                items: Vec::new(),
                has_more: false,
                next_page: 0,
            });
        }

        // Decode container identifier to vault path
        let container_path = if container_id == ROOT_ITEM_IDENTIFIER {
            "/".to_string()
        } else {
            decode_identifier(container_id)?
        };

        let container_vpath = VaultPath::new(&container_path);

        // List all entries from the vault
        let ops = Arc::clone(&self.ops);
        let container_vpath_str = container_vpath.as_str().to_string();

        let all_entries: Vec<DirEntry> = self
            .runtime
            .block_on(async move { ops.list_by_path(&container_vpath_str).await })
            .map_err(FpError::from)?;

        // Apply pagination
        let page_start = (page as usize) * ENUMERATION_PAGE_SIZE;
        let page_end = std::cmp::min(page_start + ENUMERATION_PAGE_SIZE, all_entries.len());
        let has_more = page_end < all_entries.len();
        let next_page = if has_more { page + 1 } else { 0 };

        // Convert entries in the current page
        let items: Vec<FileProviderItem> = if page_start < all_entries.len() {
            all_entries[page_start..page_end]
                .iter()
                .map(|entry| {
                    let (name, item_type, size) = match entry {
                        DirEntry::File(info) => {
                            let plaintext_size =
                                encrypted_to_plaintext_size_or_zero(info.encrypted_size);
                            (info.name.clone(), ItemType::File, plaintext_size)
                        }
                        DirEntry::Directory(info) => {
                            (info.name.clone(), ItemType::Directory, 0)
                        }
                        DirEntry::Symlink(info) => {
                            (info.name.clone(), ItemType::Symlink, 0)
                        }
                    };

                    // Compute full path for this entry
                    let entry_path = if container_path == "/" {
                        format!("/{name}")
                    } else {
                        format!("{container_path}/{name}")
                    };

                    // Cache the entry
                    self.attr_cache.insert(
                        entry_path.clone(),
                        CachedItem { item_type, size },
                    );

                    FileProviderItem::new(&entry_path, item_type, size, 0.0, 0.0)
                })
                .collect()
        } else {
            Vec::new()
        };

        trace!(
            "enumerate: returning {} items, has_more={}, next_page={}",
            items.len(),
            has_more,
            next_page
        );

        Ok(EnumerationResult {
            items,
            has_more,
            next_page,
        })
    }

    /// Get changes since a sync anchor.
    ///
    /// This is used for incremental updates to the File Provider working set.
    pub fn changes_since(&self, anchor: &str) -> FpResultChanges {
        debug!("changes_since: {}", anchor);

        let current_anchor = self.sync_anchor.load(Ordering::SeqCst);

        // TODO: Implement proper change tracking
        // For now, we return empty changes with the current anchor
        // In production, we would track file system changes and return them here

        FpResultChanges {
            result: Ok(ChangesResult {
                updated: Vec::new(),
                deleted: Vec::new(),
                anchor: current_anchor.to_string(),
            }),
        }
    }

    /// Increment the sync anchor.
    ///
    /// Call this when the vault contents change to signal the working set enumerator.
    pub fn increment_sync_anchor(&self) -> u64 {
        self.sync_anchor.fetch_add(1, Ordering::SeqCst)
    }

    /// Get the current sync anchor.
    pub fn current_anchor(&self) -> String {
        self.sync_anchor.load(Ordering::SeqCst).to_string()
    }

    /// Enumerate working set items.
    ///
    /// Returns items that should be in the working set (recently accessed/important items).
    /// For now, this returns all top-level items.
    pub fn enumerate_working_set(&self) -> FpResultWorkingSet {
        debug!("enumerate_working_set");

        // Enumerate root directory for working set
        match self.enumerate_internal(ROOT_ITEM_IDENTIFIER, 0) {
            Ok(enum_result) => FpResultWorkingSet {
                result: Ok(enum_result.items),
            },
            Err(e) => FpResultWorkingSet { result: Err(e) },
        }
    }

    /// Get working set changes since an anchor.
    ///
    /// For now, delegates to changes_since with full vault scope.
    pub fn working_set_changes_since(&self, anchor: &str) -> FpResultChanges {
        debug!("working_set_changes_since: {}", anchor);
        self.changes_since(anchor)
    }

    /// Shutdown the filesystem.
    pub fn shutdown(&mut self) {
        debug!("shutdown");
        // Clear caches - invalidate all entries by using a predicate that matches everything
        self.attr_cache.invalidate_where(|_| true);
    }
}

// ============================================================================
// Factory Function
// ============================================================================

/// Create a new FileProviderFilesystem.
///
/// - `vault_path`: Path to the Cryptomator vault directory
/// - `password`: Vault password for decryption
pub fn fp_fs_new(vault_path: &str, password: &str) -> FpResultFs {
    debug!("fp_fs_new: {}", vault_path);

    // Create a tokio runtime for async operations
    let runtime = match Runtime::new() {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            error!("Failed to create runtime: {}", e);
            return FpResultFs {
                result: Err(FpError::IoError(format!(
                    "Failed to create runtime: {e}"
                ))),
            };
        }
    };

    // Open the vault
    let ops = match VaultOperationsAsync::open(Path::new(&vault_path), password) {
        Ok(ops) => Arc::new(ops),
        Err(e) => {
            error!("Failed to open vault: {}", e);
            return FpResultFs {
                result: Err(FpError::from(e)),
            };
        }
    };

    FpResultFs {
        result: Ok(FileProviderFilesystem {
            runtime,
            ops,
            attr_cache: SyncTtlCache::with_defaults(),
            sync_anchor: AtomicU64::new(0),
        }),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_error_codes() {
        assert_eq!(FpError::NotFound("x".into()).error_code(), libc::ENOENT);
        assert_eq!(FpError::AlreadyExists("x".into()).error_code(), libc::EEXIST);
        assert_eq!(FpError::NotEmpty("x".into()).error_code(), libc::ENOTEMPTY);
    }

    #[test]
    fn test_fp_error_domains() {
        assert_eq!(
            FpError::NotFound("x".into()).error_domain(),
            "NSFileProviderErrorNoSuchItem"
        );
        assert_eq!(
            FpError::AlreadyExists("x".into()).error_domain(),
            "NSFileProviderErrorFilenameCollision"
        );
        assert_eq!(
            FpError::NotAuthenticated.error_domain(),
            "NSFileProviderErrorNotAuthenticated"
        );
    }

    #[test]
    fn test_file_provider_item_root() {
        let root = FileProviderItem::root();
        assert_eq!(root.identifier(), ROOT_ITEM_IDENTIFIER);
        assert_eq!(root.parent_identifier(), ROOT_ITEM_IDENTIFIER);
        assert_eq!(root.item_type(), ItemType::Directory as u8);
    }

    #[test]
    fn test_file_provider_item_new() {
        let item = FileProviderItem::new("/Documents/test.txt", ItemType::File, 1024, 1.0, 2.0);
        assert_eq!(item.size(), 1024);
        assert_eq!(item.item_type(), ItemType::File as u8);
        assert!((item.content_modification_date() - 1.0).abs() < f64::EPSILON);
        assert!((item.creation_date() - 2.0).abs() < f64::EPSILON);
    }
}
