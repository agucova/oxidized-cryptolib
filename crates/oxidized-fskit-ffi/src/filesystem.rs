//! Core filesystem implementation for the FFI layer.
//!
//! This module provides opaque types for Swift FFI:
//! - [`CryptoFilesystem`] - Main vault handle
//! - [`FileAttributes`] - File/directory attributes
//! - [`DirectoryEntry`] - Directory entry during enumeration
//! - [`VolumeStatistics`] - Volume space statistics
//! - `FsResult*` - Result wrapper types for error handling

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::runtime::{self, Runtime};
use tracing::{debug, error, trace, warn};

use oxidized_cryptolib::error::{VaultOperationError, VaultWriteError};
use oxidized_cryptolib::vault::config::VaultError;
use oxidized_cryptolib::fs::encrypted_to_plaintext_size_or_zero;
use oxidized_cryptolib::vault::path::{DirId, VaultPath};
use oxidized_cryptolib::vault::VaultOperationsAsync;
use oxidized_mount_common::moka_cache::SyncTtlCache;
use oxidized_mount_common::path_mapper::{EntryKind, PathEntry, PathTable};
use oxidized_mount_common::{VaultStats, WriteBuffer};

// ============================================================================
// Error Type
// ============================================================================

/// Error type for filesystem operations (maps to POSIX errno).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    /// No such file or directory (ENOENT)
    NotFound,
    /// File or directory already exists (EEXIST)
    AlreadyExists,
    /// Directory not empty (ENOTEMPTY)
    NotEmpty,
    /// Is a directory (EISDIR)
    IsDirectory,
    /// Not a directory (ENOTDIR)
    NotDirectory,
    /// Invalid argument (EINVAL)
    InvalidArgument,
    /// I/O error (EIO)
    IoError,
    /// Permission denied (EACCES)
    PermissionDenied,
    /// Operation not supported (ENOTSUP)
    NotSupported,
    /// Bad file handle (EBADF)
    BadFileHandle,
}

impl FsError {
    /// Converts to POSIX errno value.
    pub fn to_errno(self) -> i32 {
        match self {
            FsError::NotFound => libc::ENOENT,
            FsError::AlreadyExists => libc::EEXIST,
            FsError::NotEmpty => libc::ENOTEMPTY,
            FsError::IsDirectory => libc::EISDIR,
            FsError::NotDirectory => libc::ENOTDIR,
            FsError::InvalidArgument => libc::EINVAL,
            FsError::IoError => libc::EIO,
            FsError::PermissionDenied => libc::EACCES,
            FsError::NotSupported => libc::ENOTSUP,
            FsError::BadFileHandle => libc::EBADF,
        }
    }

    /// Maps a string error message to the appropriate FsError.
    fn from_message(msg: &str) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("not found") || lower.contains("no such") {
            FsError::NotFound
        } else if lower.contains("already exists") || lower.contains("exists") {
            FsError::AlreadyExists
        } else if lower.contains("not empty") {
            FsError::NotEmpty
        } else if lower.contains("is a directory") {
            FsError::IsDirectory
        } else if lower.contains("not a directory") {
            FsError::NotDirectory
        } else if lower.contains("permission") || lower.contains("access denied") {
            FsError::PermissionDenied
        } else if lower.contains("not supported") || lower.contains("unsupported") {
            FsError::NotSupported
        } else if lower.contains("invalid") {
            FsError::InvalidArgument
        } else {
            FsError::IoError
        }
    }
}

impl From<VaultOperationError> for FsError {
    fn from(e: VaultOperationError) -> Self {
        match &e {
            VaultOperationError::PathNotFound { .. } => FsError::NotFound,
            VaultOperationError::FileNotFound { .. } => FsError::NotFound,
            VaultOperationError::DirectoryNotFound { .. } => FsError::NotFound,
            VaultOperationError::SymlinkNotFound { .. } => FsError::NotFound,
            VaultOperationError::NotAFile { .. } => FsError::IsDirectory,
            VaultOperationError::NotADirectory { .. } => FsError::NotDirectory,
            VaultOperationError::NotASymlink { .. } => FsError::InvalidArgument,
            VaultOperationError::EmptyPath => FsError::InvalidArgument,
            _ => {
                let msg = e.to_string();
                FsError::from_message(&msg)
            }
        }
    }
}

impl From<VaultWriteError> for FsError {
    fn from(e: VaultWriteError) -> Self {
        match &e {
            VaultWriteError::FileNotFound { .. } => FsError::NotFound,
            VaultWriteError::DirectoryNotFound { .. } => FsError::NotFound,
            VaultWriteError::FileAlreadyExists { .. } => FsError::AlreadyExists,
            VaultWriteError::DirectoryAlreadyExists { .. } => FsError::AlreadyExists,
            VaultWriteError::SymlinkAlreadyExists { .. } => FsError::AlreadyExists,
            VaultWriteError::PathExists { .. } => FsError::AlreadyExists,
            VaultWriteError::DirectoryNotEmpty { .. } => FsError::NotEmpty,
            _ => {
                let msg = e.to_string();
                FsError::from_message(&msg)
            }
        }
    }
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::NotFound => FsError::NotFound,
            ErrorKind::AlreadyExists => FsError::AlreadyExists,
            ErrorKind::PermissionDenied => FsError::PermissionDenied,
            ErrorKind::InvalidInput | ErrorKind::InvalidData => FsError::InvalidArgument,
            ErrorKind::Unsupported => FsError::NotSupported,
            _ => FsError::IoError,
        }
    }
}

impl From<VaultError> for FsError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Io(io_err) => FsError::from(io_err),
            _ => {
                // MasterKeyExtraction, ClaimValidation, KeyClone errors
                // are all configuration/auth errors
                FsError::PermissionDenied
            }
        }
    }
}

// ============================================================================
// Result Wrapper Types for FFI
// ============================================================================

/// Result wrapper for CryptoFilesystem creation.
pub struct FsResultFs(Result<CryptoFilesystem, FsError>);

impl FsResultFs {
    /// Checks if the result is successful.
    pub fn result_fs_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_fs_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }

    /// Unwraps the filesystem (panics if error).
    pub fn result_fs_unwrap(self) -> CryptoFilesystem {
        self.0.expect("FsResultFs unwrap called on error")
    }
}

/// Result wrapper for FileAttributes.
pub struct FsResultAttrs(Result<FileAttributes, FsError>);

impl FsResultAttrs {
    /// Checks if the result is successful.
    pub fn result_attrs_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_attrs_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }

    /// Unwraps the attributes (panics if error).
    pub fn result_attrs_unwrap(self) -> FileAttributes {
        self.0.expect("FsResultAttrs unwrap called on error")
    }
}

/// Result wrapper for VolumeStatistics.
pub struct FsResultStats(Result<VolumeStatistics, FsError>);

impl FsResultStats {
    /// Checks if the result is successful.
    pub fn result_stats_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_stats_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }

    /// Unwraps the statistics (panics if error).
    pub fn result_stats_unwrap(self) -> VolumeStatistics {
        self.0.expect("FsResultStats unwrap called on error")
    }
}

/// Result wrapper for Vec<DirectoryEntry>.
pub struct FsResultDirEntries(Result<Vec<DirectoryEntry>, FsError>);

impl FsResultDirEntries {
    /// Checks if the result is successful.
    pub fn result_dir_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_dir_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }

    /// Unwraps the entries (panics if error).
    pub fn result_dir_unwrap(self) -> Vec<DirectoryEntry> {
        self.0.expect("FsResultDirEntries unwrap called on error")
    }
}

/// Result wrapper for file handles (u64).
pub struct FsResultHandle(Result<u64, FsError>);

impl FsResultHandle {
    /// Checks if the result is successful.
    pub fn result_handle_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_handle_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }

    /// Unwraps the handle (returns 0 if error).
    pub fn result_handle_unwrap(&self) -> u64 {
        self.0.clone().unwrap_or(0)
    }
}

/// Result wrapper for unit (void) operations.
pub struct FsResultUnit(Result<(), FsError>);

impl FsResultUnit {
    /// Checks if the result is successful.
    pub fn result_unit_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_unit_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }
}

/// Result wrapper for byte data.
pub struct FsResultBytes(Result<Vec<u8>, FsError>);

impl FsResultBytes {
    /// Checks if the result is successful.
    pub fn result_bytes_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_bytes_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }

    /// Unwraps the bytes (panics if error).
    pub fn result_bytes_unwrap(self) -> Vec<u8> {
        self.0.expect("FsResultBytes unwrap called on error")
    }
}

/// Result wrapper for bytes written (i64).
pub struct FsResultWritten(Result<i64, FsError>);

impl FsResultWritten {
    /// Checks if the result is successful.
    pub fn result_written_is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Gets the error code (0 if success).
    pub fn result_written_error(&self) -> i32 {
        match &self.0 {
            Ok(_) => 0,
            Err(e) => e.to_errno(),
        }
    }

    /// Unwraps the count (returns 0 if error).
    pub fn result_written_unwrap(&self) -> i64 {
        self.0.clone().unwrap_or(0)
    }
}

/// Factory function exposed to FFI for CryptoFilesystem creation.
pub fn crypto_fs_new(vault_path: String, password: String) -> FsResultFs {
    FsResultFs(CryptoFilesystem::new_internal(vault_path, password))
}

/// Root item ID (FSKit reserves ID 1, so we use 2).
pub const ROOT_ITEM_ID: u64 = 2;

/// Handle for open files.
enum FileHandle {
    /// Read-only handle with in-memory content.
    ReadOnly {
        /// Decrypted file content.
        content: Vec<u8>,
    },
    /// Write handle with in-memory buffer.
    WriteBuffer(WriteBuffer),
}

/// File type enumeration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file
    Regular,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
}

/// Item entry in the path table.
type ItemEntry = PathEntry;

/// Item kind alias.
type ItemKind = EntryKind;

// ============================================================================
// Opaque FFI Types
// ============================================================================

/// Opaque file attributes exposed to Swift.
pub struct FileAttributes {
    item_id: u64,
    file_type: FileType,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl FileAttributes {
    fn new(item_id: u64, file_type: FileType, size: u64, uid: u32, gid: u32) -> Self {
        let mode = match file_type {
            FileType::Regular => 0o644,
            FileType::Directory => 0o755,
            FileType::Symlink => 0o777,
        };
        Self {
            item_id,
            file_type,
            size,
            mode,
            uid,
            gid,
        }
    }

    /// Gets the item ID.
    pub fn attr_item_id(&self) -> u64 {
        self.item_id
    }

    /// Checks if this is a directory.
    pub fn attr_is_directory(&self) -> bool {
        matches!(self.file_type, FileType::Directory)
    }

    /// Checks if this is a regular file.
    pub fn attr_is_file(&self) -> bool {
        matches!(self.file_type, FileType::Regular)
    }

    /// Checks if this is a symlink.
    pub fn attr_is_symlink(&self) -> bool {
        matches!(self.file_type, FileType::Symlink)
    }

    /// Gets the file size.
    pub fn attr_size(&self) -> u64 {
        self.size
    }

    /// Gets the file mode.
    pub fn attr_mode(&self) -> u32 {
        self.mode
    }

    /// Gets the owner UID.
    pub fn attr_uid(&self) -> u32 {
        self.uid
    }

    /// Gets the owner GID.
    pub fn attr_gid(&self) -> u32 {
        self.gid
    }
}

/// Opaque directory entry exposed to Swift.
pub struct DirectoryEntry {
    name: String,
    item_id: u64,
    file_type: FileType,
    size: u64,
}

impl DirectoryEntry {
    fn new(name: String, item_id: u64, file_type: FileType, size: u64) -> Self {
        Self {
            name,
            item_id,
            file_type,
            size,
        }
    }

    /// Gets the entry name as UTF-8 bytes.
    pub fn entry_name(&self) -> Vec<u8> {
        self.name.clone().into_bytes()
    }

    /// Gets the item ID.
    pub fn entry_item_id(&self) -> u64 {
        self.item_id
    }

    /// Checks if this is a directory.
    pub fn entry_is_directory(&self) -> bool {
        matches!(self.file_type, FileType::Directory)
    }

    /// Checks if this is a regular file.
    pub fn entry_is_file(&self) -> bool {
        matches!(self.file_type, FileType::Regular)
    }

    /// Checks if this is a symlink.
    pub fn entry_is_symlink(&self) -> bool {
        matches!(self.file_type, FileType::Symlink)
    }

    /// Gets the file size.
    pub fn entry_size(&self) -> u64 {
        self.size
    }
}

/// Opaque volume statistics exposed to Swift.
pub struct VolumeStatistics {
    total_bytes: u64,
    available_bytes: u64,
    used_bytes: u64,
    total_inodes: u64,
    available_inodes: u64,
    block_size: u32,
}

impl VolumeStatistics {
    fn new(
        total_bytes: u64,
        available_bytes: u64,
        total_inodes: u64,
        available_inodes: u64,
        block_size: u32,
    ) -> Self {
        Self {
            total_bytes,
            available_bytes,
            used_bytes: total_bytes.saturating_sub(available_bytes),
            total_inodes,
            available_inodes,
            block_size,
        }
    }

    /// Gets total space in bytes.
    pub fn stats_total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Gets available space in bytes.
    pub fn stats_available_bytes(&self) -> u64 {
        self.available_bytes
    }

    /// Gets used space in bytes.
    pub fn stats_used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Gets total inode count.
    pub fn stats_total_inodes(&self) -> u64 {
        self.total_inodes
    }

    /// Gets available inode count.
    pub fn stats_available_inodes(&self) -> u64 {
        self.available_inodes
    }

    /// Gets block size.
    pub fn stats_block_size(&self) -> u32 {
        self.block_size
    }
}

// ============================================================================
// Main Filesystem
// ============================================================================

/// Cached file attributes.
#[derive(Clone)]
struct CachedAttr {
    file_type: FileType,
    size: u64,
}

/// Opaque handle to a Cryptomator vault filesystem.
///
/// This struct is the main FFI interface, providing all filesystem operations
/// needed by the Swift FSKit extension.
pub struct CryptoFilesystem {
    /// Async vault operations (thread-safe).
    ops: Arc<VaultOperationsAsync>,
    /// Path table for item_id <-> path mapping.
    items: PathTable<u64, ItemEntry>,
    /// Open file handles.
    handles: DashMap<u64, FileHandle>,
    /// Next handle ID.
    next_handle_id: AtomicU64,
    /// Attribute cache.
    attr_cache: SyncTtlCache<u64, CachedAttr>,
    /// Statistics for monitoring.
    #[allow(dead_code)]
    stats: Arc<VaultStats>,
    /// User ID for file ownership.
    uid: u32,
    /// Group ID for file ownership.
    gid: u32,
    /// Tokio runtime for async operations.
    runtime: Runtime,
    /// Last enumeration cookies per directory.
    enum_cookies: DashMap<u64, u64>,
}

impl CryptoFilesystem {
    /// Opens a Cryptomator vault at the given path (internal implementation).
    fn new_internal(vault_path: String, password: String) -> Result<Self, FsError> {
        // Create tokio runtime for async operations
        let runtime = runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .map_err(|e| {
                error!("Failed to create runtime: {e}");
                FsError::IoError
            })?;

        // Open vault - extracts key, reads config
        let ops = VaultOperationsAsync::open(Path::new(&vault_path), &password)
            .map_err(|e| {
                error!("Failed to open vault: {e}");
                FsError::from(e)
            })?
            .into_shared();

        // Get current user/group
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Create path table with root pre-allocated
        let items = PathTable::with_root(
            ROOT_ITEM_ID,
            3, // Start at 3 since 2 is root
            PathEntry::new(VaultPath::root(), ItemKind::Root),
        );

        debug!(
            vault_path = %vault_path,
            uid = uid,
            gid = gid,
            "CryptoFilesystem initialized"
        );

        Ok(Self {
            ops,
            items,
            handles: DashMap::new(),
            next_handle_id: AtomicU64::new(1),
            attr_cache: SyncTtlCache::with_defaults(),
            stats: Arc::new(VaultStats::new()),
            uid,
            gid,
            runtime,
            enum_cookies: DashMap::new(),
        })
    }

    /// Returns the root item ID.
    pub fn get_root_item_id(&self) -> u64 {
        ROOT_ITEM_ID
    }

    /// Shuts down the filesystem.
    pub fn shutdown(&mut self) {
        debug!("Shutting down CryptoFilesystem");
        self.handles.clear();
        // Runtime will be dropped when self is dropped
    }

    /// Gets volume statistics.
    pub fn get_volume_stats(&self) -> FsResultStats {
        FsResultStats(self.get_volume_stats_internal())
    }

    fn get_volume_stats_internal(&self) -> Result<VolumeStatistics, FsError> {
        let vault_path = self.ops.vault_path();
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

        let path_cstr = std::ffi::CString::new(vault_path.to_string_lossy().as_bytes())
            .map_err(|_| FsError::InvalidArgument)?;

        let ret = unsafe { libc::statvfs(path_cstr.as_ptr(), &mut stat) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            error!("statvfs failed: {}", err);
            return Err(FsError::from(err));
        }

        Ok(VolumeStatistics::new(
            (stat.f_blocks as u64) * (stat.f_frsize as u64),
            (stat.f_bavail as u64) * (stat.f_frsize as u64),
            stat.f_files as u64,
            stat.f_ffree as u64,
            stat.f_frsize as u32,
        ))
    }

    /// Looks up an item by name in a parent directory.
    pub fn lookup(&self, parent_id: u64, name: String) -> FsResultAttrs {
        FsResultAttrs(self.lookup_internal(parent_id, name))
    }

    fn lookup_internal(&self, parent_id: u64, name: String) -> Result<FileAttributes, FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let parent_entry = self.items.get(parent_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let parent_path = parent_entry.path.clone();
        let parent_dir_id = match &parent_entry.kind {
            ItemKind::Root => DirId::root(),
            ItemKind::Directory { dir_id } => dir_id.clone(),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        drop(parent_entry);

        // Try to find the item in the vault
        let ops = Arc::clone(&self.ops);
        let name_clone = name.clone();
        let parent_dir_id_clone = parent_dir_id.clone();

        let result: Result<(ItemKind, FileType), FsError> = self.runtime.block_on(async move {
            // Try file first
            if ops.find_file(&parent_dir_id_clone, &name_clone).await.is_ok() {
                return Ok((
                    ItemKind::File {
                        dir_id: parent_dir_id_clone.clone(),
                        name: name_clone.clone(),
                    },
                    FileType::Regular,
                ));
            }

            // Try directory - returns Option<VaultDirectoryInfo>
            if let Ok(Some(dir_info)) = ops.find_directory(&parent_dir_id_clone, &name_clone).await {
                return Ok((
                    ItemKind::Directory { dir_id: dir_info.directory_id },
                    FileType::Directory,
                ));
            }

            // Try symlink
            if ops
                .find_symlink(&parent_dir_id_clone, &name_clone)
                .await
                .is_ok()
            {
                return Ok((
                    ItemKind::Symlink {
                        dir_id: parent_dir_id_clone,
                        name: name_clone,
                    },
                    FileType::Symlink,
                ));
            }

            Err(FsError::NotFound)
        });
        let (kind, file_type) = result.map_err(|e| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            e
        })?;

        let child_path = parent_path.join(&name);

        // Allocate item ID
        let kind_clone: ItemKind = kind.clone();
        let item_id = self
            .items
            .get_or_insert_with(child_path, || PathEntry::new(VaultPath::new(&name), kind_clone));

        // Get size if it's a file
        let size = if file_type == FileType::Regular {
            self.get_file_size_cached(item_id, &kind).unwrap_or(0)
        } else {
            0
        };

        self.stats.record_metadata_latency(start.elapsed());
        Ok(FileAttributes::new(item_id, file_type, size, self.uid, self.gid))
    }

    /// Gets attributes of an item by ID.
    pub fn get_attributes(&self, item_id: u64) -> FsResultAttrs {
        FsResultAttrs(self.get_attributes_internal(item_id))
    }

    fn get_attributes_internal(&self, item_id: u64) -> Result<FileAttributes, FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let entry = self.items.get(item_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let kind = entry.kind.clone();
        drop(entry);

        let (file_type, size) = match &kind {
            ItemKind::Root | ItemKind::Directory { .. } => (FileType::Directory, 0),
            ItemKind::File { .. } => {
                let size = self.get_file_size_cached(item_id, &kind).unwrap_or(0);
                (FileType::Regular, size)
            }
            ItemKind::Symlink { .. } => {
                let target = self.read_symlink_string(item_id).unwrap_or_default();
                (FileType::Symlink, target.len() as u64)
            }
        };

        self.stats.record_metadata_latency(start.elapsed());
        Ok(FileAttributes::new(item_id, file_type, size, self.uid, self.gid))
    }

    /// Enumerates directory contents.
    pub fn enumerate_directory(&self, item_id: u64, cookie: u64) -> FsResultDirEntries {
        FsResultDirEntries(self.enumerate_directory_internal(item_id, cookie))
    }

    fn enumerate_directory_internal(
        &self,
        item_id: u64,
        cookie: u64,
    ) -> Result<Vec<DirectoryEntry>, FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let entry = self.items.get(item_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let dir_id = match &entry.kind {
            ItemKind::Root => DirId::root(),
            ItemKind::Directory { dir_id } => dir_id.clone(),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        let parent_path = entry.path.clone();
        drop(entry);

        let ops = Arc::clone(&self.ops);

        // List all entries from the vault
        let (files, dirs, symlinks) = self.runtime.block_on(async move {
            let files = ops.list_files(&dir_id).await.unwrap_or_default();
            let dirs = ops.list_directories(&dir_id).await.unwrap_or_default();
            let symlinks = ops.list_symlinks(&dir_id).await.unwrap_or_default();
            (files, dirs, symlinks)
        });

        // Combine all entries
        let mut all_entries: Vec<(String, ItemKind, FileType)> = Vec::new();

        // Re-get dir_id since we moved it
        let entry = self.items.get(item_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let dir_id = match &entry.kind {
            ItemKind::Root => DirId::root(),
            ItemKind::Directory { dir_id } => dir_id.clone(),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        drop(entry);

        for file_info in files {
            all_entries.push((
                file_info.name.clone(),
                ItemKind::File {
                    dir_id: dir_id.clone(),
                    name: file_info.name,
                },
                FileType::Regular,
            ));
        }

        for dir_info in dirs {
            all_entries.push((
                dir_info.name.clone(),
                ItemKind::Directory { dir_id: dir_info.directory_id },
                FileType::Directory,
            ));
        }

        for symlink_info in symlinks {
            all_entries.push((
                symlink_info.name.clone(),
                ItemKind::Symlink {
                    dir_id: dir_id.clone(),
                    name: symlink_info.name,
                },
                FileType::Symlink,
            ));
        }

        // Apply pagination
        let page_start = cookie as usize;
        let page_size = 100;
        let end = std::cmp::min(page_start + page_size, all_entries.len());
        let has_more = end < all_entries.len();

        // Store next cookie
        let next_cookie = if has_more { end as u64 } else { 0 };
        self.enum_cookies.insert(item_id, next_cookie);

        let entries: Vec<DirectoryEntry> = all_entries[page_start..end]
            .iter()
            .map(|(name, kind, file_type)| {
                let child_path = parent_path.join(name);
                let child_id = self
                    .items
                    .get_or_insert_with(child_path, || PathEntry::new(VaultPath::new(&name), kind.clone()));

                let size = if *file_type == FileType::Regular {
                    self.get_file_size_cached(child_id, kind).unwrap_or(0)
                } else {
                    0
                };

                DirectoryEntry::new(name.clone(), child_id, *file_type, size)
            })
            .collect();

        self.stats.record_metadata_latency(start.elapsed());
        Ok(entries)
    }

    /// Gets the next enumeration cookie for a directory.
    pub fn get_enumeration_cookie(&self, item_id: u64, _cookie: u64) -> u64 {
        self.enum_cookies.get(&item_id).map(|v| *v).unwrap_or(0)
    }

    /// Opens a file for reading or writing.
    pub fn open_file(&self, item_id: u64, for_write: bool) -> FsResultHandle {
        FsResultHandle(self.open_file_internal(item_id, for_write))
    }

    fn open_file_internal(&self, item_id: u64, for_write: bool) -> Result<u64, FsError> {
        let entry = self
            .items
            .get(item_id)
            .ok_or(FsError::NotFound)?;
        let (dir_id, name) = match &entry.kind {
            ItemKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            ItemKind::Directory { .. } | ItemKind::Root => return Err(FsError::IsDirectory),
            ItemKind::Symlink { .. } => return Err(FsError::InvalidArgument),
        };
        drop(entry);

        let ops = Arc::clone(&self.ops);

        // Clone dir_id and name before moving into async block
        let dir_id_for_read = dir_id.clone();
        let name_for_read = name.clone();

        // Load file content into memory
        let content = self.runtime.block_on(async move {
            match ops.read_file(&dir_id_for_read, &name_for_read).await {
                Ok(decrypted_file) => decrypted_file.content,
                Err(_) => Vec::new(), // File might be new/empty
            }
        });

        let handle = if for_write {
            FileHandle::WriteBuffer(WriteBuffer::new(dir_id, name, content))
        } else {
            FileHandle::ReadOnly { content }
        };

        let handle_id = self.next_handle_id.fetch_add(1, Ordering::SeqCst);
        self.handles.insert(handle_id, handle);

        trace!(handle_id = handle_id, for_write = for_write, "Opened file");

        Ok(handle_id)
    }

    /// Closes an open file handle.
    pub fn close_file(&self, handle_id: u64) -> FsResultUnit {
        FsResultUnit(self.close_file_internal(handle_id))
    }

    fn close_file_internal(&self, handle_id: u64) -> Result<(), FsError> {
        let (_, handle) = self
            .handles
            .remove(&handle_id)
            .ok_or(FsError::BadFileHandle)?;

        // If it's a write buffer, flush to vault
        if let FileHandle::WriteBuffer(buffer) = handle {
            if buffer.is_dirty() {
                let ops = Arc::clone(&self.ops);
                let dir_id = buffer.dir_id().clone();
                let name = buffer.filename().to_string();
                let data = buffer.into_content();

                self.runtime
                    .block_on(async move { ops.write_file(&dir_id, &name, &data).await })
                    .map_err(|e| {
                        error!("Failed to flush write buffer: {e}");
                        FsError::from(e)
                    })?;
            }
        }

        trace!(handle_id = handle_id, "Closed file");
        Ok(())
    }

    /// Reads data from an open file.
    pub fn read_file(&self, handle_id: u64, offset: i64, length: i64) -> FsResultBytes {
        FsResultBytes(self.read_file_internal(handle_id, offset, length))
    }

    fn read_file_internal(&self, handle_id: u64, offset: i64, length: i64) -> Result<Vec<u8>, FsError> {
        let handle = self
            .handles
            .get(&handle_id)
            .ok_or(FsError::BadFileHandle)?;

        let offset = offset as usize;
        let length = length as usize;

        let data: &[u8] = match &*handle {
            FileHandle::ReadOnly { content } => content,
            FileHandle::WriteBuffer(buffer) => buffer.content(),
        };

        if offset >= data.len() {
            return Ok(Vec::new());
        }

        let end = std::cmp::min(offset + length, data.len());
        Ok(data[offset..end].to_vec())
    }

    /// Writes data to an open file.
    pub fn write_file(&self, handle_id: u64, offset: i64, data: Vec<u8>) -> FsResultWritten {
        FsResultWritten(self.write_file_internal(handle_id, offset, data))
    }

    fn write_file_internal(&self, handle_id: u64, offset: i64, data: Vec<u8>) -> Result<i64, FsError> {
        let mut handle = self
            .handles
            .get_mut(&handle_id)
            .ok_or(FsError::BadFileHandle)?;

        match &mut *handle {
            FileHandle::ReadOnly { .. } => Err(FsError::PermissionDenied),
            FileHandle::WriteBuffer(buffer) => {
                buffer.write(offset as u64, &data);
                Ok(data.len() as i64)
            }
        }
    }

    /// Creates a new empty file.
    pub fn create_file(&self, parent_id: u64, name: String) -> FsResultAttrs {
        FsResultAttrs(self.create_file_internal(parent_id, name))
    }

    fn create_file_internal(&self, parent_id: u64, name: String) -> Result<FileAttributes, FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let entry = self.items.get(parent_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let (parent_path, dir_id) = match &entry.kind {
            ItemKind::Root => (entry.path.clone(), DirId::root()),
            ItemKind::Directory { dir_id } => (entry.path.clone(), dir_id.clone()),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        drop(entry);

        let ops = Arc::clone(&self.ops);
        let name_clone = name.clone();
        let dir_id_clone = dir_id.clone();

        // Create empty file
        self.runtime
            .block_on(async move { ops.write_file(&dir_id_clone, &name_clone, &[]).await })
            .map_err(|e| {
                error!("Failed to create file: {e}");
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                FsError::from(e)
            })?;

        // Allocate item ID
        let child_path = parent_path.join(&name);
        let item_id = self.items.get_or_insert_with(child_path, || {
            PathEntry::new(
                VaultPath::new(&name),
                ItemKind::File {
                    dir_id,
                    name: name.clone(),
                },
            )
        });

        self.stats.record_metadata_latency(start.elapsed());
        Ok(FileAttributes::new(item_id, FileType::Regular, 0, self.uid, self.gid))
    }

    /// Creates a new directory.
    pub fn create_directory(&self, parent_id: u64, name: String) -> FsResultAttrs {
        FsResultAttrs(self.create_directory_internal(parent_id, name))
    }

    fn create_directory_internal(&self, parent_id: u64, name: String) -> Result<FileAttributes, FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let entry = self.items.get(parent_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let (parent_path, parent_dir_id) = match &entry.kind {
            ItemKind::Root => (entry.path.clone(), DirId::root()),
            ItemKind::Directory { dir_id } => (entry.path.clone(), dir_id.clone()),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        drop(entry);

        let ops = Arc::clone(&self.ops);
        let name_clone = name.clone();

        // Create directory
        let new_dir_id = self
            .runtime
            .block_on(async move { ops.create_directory(&parent_dir_id, &name_clone).await })
            .map_err(|e| {
                error!("Failed to create directory: {e}");
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                FsError::from(e)
            })?;

        // Allocate item ID
        let child_path = parent_path.join(&name);
        let item_id = self.items.get_or_insert_with(child_path, || {
            PathEntry::new(
                VaultPath::new(&name),
                ItemKind::Directory { dir_id: new_dir_id },
            )
        });

        self.stats.record_metadata_latency(start.elapsed());
        Ok(FileAttributes::new(item_id, FileType::Directory, 0, self.uid, self.gid))
    }

    /// Creates a new symbolic link.
    pub fn create_symlink(&self, parent_id: u64, name: String, target: String) -> FsResultAttrs {
        FsResultAttrs(self.create_symlink_internal(parent_id, name, target))
    }

    fn create_symlink_internal(
        &self,
        parent_id: u64,
        name: String,
        target: String,
    ) -> Result<FileAttributes, FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let entry = self.items.get(parent_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let (parent_path, dir_id) = match &entry.kind {
            ItemKind::Root => (entry.path.clone(), DirId::root()),
            ItemKind::Directory { dir_id } => (entry.path.clone(), dir_id.clone()),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        drop(entry);

        let ops = Arc::clone(&self.ops);
        let name_clone = name.clone();
        let target_clone = target.clone();
        let dir_id_clone = dir_id.clone();

        // Create symlink
        self.runtime
            .block_on(async move {
                ops.create_symlink(&dir_id_clone, &name_clone, &target_clone)
                    .await
            })
            .map_err(|e| {
                error!("Failed to create symlink: {e}");
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                FsError::from(e)
            })?;

        // Allocate item ID
        let child_path = parent_path.join(&name);
        let item_id = self.items.get_or_insert_with(child_path, || {
            PathEntry::new(
                VaultPath::new(&name),
                ItemKind::Symlink {
                    dir_id,
                    name: name.clone(),
                },
            )
        });

        self.stats.record_metadata_latency(start.elapsed());
        Ok(FileAttributes::new(
            item_id,
            FileType::Symlink,
            target.len() as u64,
            self.uid,
            self.gid,
        ))
    }

    /// Removes a file, directory, or symlink.
    pub fn remove(&self, parent_id: u64, name: String, item_id: u64) -> FsResultUnit {
        FsResultUnit(self.remove_internal(parent_id, name, item_id))
    }

    fn remove_internal(&self, parent_id: u64, name: String, item_id: u64) -> Result<(), FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let item_entry = self.items.get(item_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let kind = item_entry.kind.clone();
        let path = item_entry.path.clone();
        drop(item_entry);

        let parent_entry = self.items.get(parent_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let parent_dir_id = match &parent_entry.kind {
            ItemKind::Root => DirId::root(),
            ItemKind::Directory { dir_id } => dir_id.clone(),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        drop(parent_entry);

        let ops = Arc::clone(&self.ops);
        let name_clone = name.clone();

        match kind {
            ItemKind::File { .. } => {
                self.runtime
                    .block_on(async move { ops.delete_file(&parent_dir_id, &name_clone).await })
                    .map_err(|e| {
                        error!("Failed to delete file: {e}");
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        FsError::from(e)
                    })?;
            }
            ItemKind::Directory { .. } => {
                let name_for_dir = name.clone();
                self.runtime
                    .block_on(async move { ops.delete_directory(&parent_dir_id, &name_for_dir).await })
                    .map_err(|e| {
                        error!("Failed to delete directory: {e}");
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        FsError::from(e)
                    })?;
            }
            ItemKind::Symlink { .. } => {
                let name_for_symlink = name.clone();
                self.runtime
                    .block_on(async move { ops.delete_symlink(&parent_dir_id, &name_for_symlink).await })
                    .map_err(|e| {
                        error!("Failed to delete symlink: {e}");
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        FsError::from(e)
                    })?;
            }
            ItemKind::Root => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::PermissionDenied);
            }
        }

        // Remove from path table
        self.items.remove_by_path(&path);
        // Invalidate cache
        self.attr_cache.invalidate(&item_id);

        self.stats.record_metadata_latency(start.elapsed());
        Ok(())
    }

    /// Renames or moves an item.
    pub fn rename(
        &self,
        src_parent_id: u64,
        src_name: String,
        dst_parent_id: u64,
        dst_name: String,
        item_id: u64,
    ) -> FsResultUnit {
        FsResultUnit(self.rename_internal(src_parent_id, src_name, dst_parent_id, dst_name, item_id))
    }

    fn rename_internal(
        &self,
        src_parent_id: u64,
        src_name: String,
        dst_parent_id: u64,
        dst_name: String,
        item_id: u64,
    ) -> Result<(), FsError> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let item_entry = self.items.get(item_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let kind = item_entry.kind.clone();
        let old_path = item_entry.path.clone();
        drop(item_entry);

        let src_parent = self.items.get(src_parent_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let src_dir_id = match &src_parent.kind {
            ItemKind::Root => DirId::root(),
            ItemKind::Directory { dir_id } => dir_id.clone(),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        drop(src_parent);

        let dst_parent = self.items.get(dst_parent_id).ok_or_else(|| {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            FsError::NotFound
        })?;
        let dst_dir_id = match &dst_parent.kind {
            ItemKind::Root => DirId::root(),
            ItemKind::Directory { dir_id } => dir_id.clone(),
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::NotDirectory);
            }
        };
        let dst_parent_path = dst_parent.path.clone();
        drop(dst_parent);

        let ops = Arc::clone(&self.ops);
        let src_name_clone = src_name.clone();
        let dst_name_clone = dst_name.clone();

        match kind {
            ItemKind::File { .. } => {
                if src_parent_id == dst_parent_id {
                    // Same directory rename
                    self.runtime
                        .block_on(async move {
                            ops.rename_file(&src_dir_id, &src_name_clone, &dst_name_clone)
                                .await
                        })
                        .map_err(|e| {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            FsError::from(e)
                        })?;
                } else if src_name == dst_name {
                    // Move to different directory, same name
                    self.runtime
                        .block_on(async move {
                            ops.move_file(&src_dir_id, &src_name_clone, &dst_dir_id)
                                .await
                        })
                        .map_err(|e| {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            FsError::from(e)
                        })?;
                } else {
                    // Move and rename
                    self.runtime
                        .block_on(async move {
                            ops.move_and_rename_file(
                                &src_dir_id,
                                &src_name_clone,
                                &dst_dir_id,
                                &dst_name_clone,
                            )
                            .await
                        })
                        .map_err(|e| {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            FsError::from(e)
                        })?;
                }
            }
            ItemKind::Directory { dir_id: _ } => {
                // For directory rename, use the parent's dir_id, not the directory's own ID
                if src_parent_id != dst_parent_id {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(FsError::NotSupported); // Cross-directory move not supported
                }
                let src_name_for_dir = src_name.clone();
                let dst_name_for_dir = dst_name.clone();
                self.runtime
                    .block_on(async move {
                        ops.rename_directory(&src_dir_id, &src_name_for_dir, &dst_name_for_dir)
                            .await
                    })
                    .map_err(|e| {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        FsError::from(e)
                    })?;
            }
            ItemKind::Symlink { .. } => {
                // Symlink rename is implemented as: read target, delete old, create new
                if src_parent_id != dst_parent_id {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(FsError::NotSupported); // Cross-directory symlink move not supported
                }
                let src_name_for_sym = src_name.clone();
                let dst_name_for_sym = dst_name.clone();

                // Read the symlink target
                let target = self.runtime
                    .block_on(async {
                        ops.read_symlink(&src_dir_id, &src_name_for_sym).await
                    })
                    .map_err(|e| {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        FsError::from(e)
                    })?;

                // Delete the old symlink
                let ops2 = Arc::clone(&self.ops);
                let src_dir_id2 = src_dir_id.clone();
                let src_name_for_delete = src_name.clone();
                self.runtime
                    .block_on(async move {
                        ops2.delete_symlink(&src_dir_id2, &src_name_for_delete).await
                    })
                    .map_err(|e| {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        FsError::from(e)
                    })?;

                // Create the new symlink with the new name
                let ops3 = Arc::clone(&self.ops);
                let src_dir_id3 = src_dir_id.clone();
                self.runtime
                    .block_on(async move {
                        ops3.create_symlink(&src_dir_id3, &dst_name_for_sym, &target).await
                    })
                    .map_err(|e| {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        FsError::from(e)
                    })?;
            }
            ItemKind::Root => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::PermissionDenied);
            }
        }

        // Update path table
        let new_path = dst_parent_path.join(&dst_name);
        self.items
            .update_path(item_id, &old_path, new_path, |entry, path| {
                entry.path = path;
            });

        // Invalidate cache
        self.attr_cache.invalidate(&item_id);

        self.stats.record_metadata_latency(start.elapsed());
        Ok(())
    }

    /// Reads the target of a symbolic link (returns UTF-8 bytes for FFI).
    pub fn read_symlink(&self, item_id: u64) -> FsResultBytes {
        FsResultBytes(self.read_symlink_string(item_id).map(|s| s.into_bytes()))
    }

    /// Internal: reads symlink target as String.
    fn read_symlink_string(&self, item_id: u64) -> Result<String, FsError> {
        let entry = self
            .items
            .get(item_id)
            .ok_or(FsError::NotFound)?;
        let (dir_id, name) = match &entry.kind {
            ItemKind::Symlink { dir_id, name } => (dir_id.clone(), name.clone()),
            _ => return Err(FsError::InvalidArgument),
        };
        drop(entry);

        let ops = Arc::clone(&self.ops);

        self.runtime
            .block_on(async move { ops.read_symlink(&dir_id, &name).await })
            .map_err(|e| FsError::from(e))
    }

    /// Truncates a file to the specified size.
    pub fn truncate(&self, item_id: u64, size: u64) -> FsResultUnit {
        FsResultUnit(self.truncate_internal(item_id, size))
    }

    fn truncate_internal(&self, item_id: u64, size: u64) -> Result<(), FsError> {
        let entry = self
            .items
            .get(item_id)
            .ok_or(FsError::NotFound)?;
        let (dir_id, name) = match &entry.kind {
            ItemKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            ItemKind::Directory { .. } | ItemKind::Root => {
                return Err(FsError::IsDirectory)
            }
            ItemKind::Symlink { .. } => return Err(FsError::InvalidArgument),
        };
        drop(entry);

        let ops = Arc::clone(&self.ops);

        // Read current content
        let decrypted_file = self
            .runtime
            .block_on(async move { ops.read_file(&dir_id, &name).await })
            .map_err(|e| FsError::from(e))?;

        // Get the content and truncate or extend
        let mut content = decrypted_file.content;
        content.resize(size as usize, 0);

        // Write back
        let ops = Arc::clone(&self.ops);
        let entry = self
            .items
            .get(item_id)
            .ok_or(FsError::NotFound)?;
        let (dir_id, name) = match &entry.kind {
            ItemKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            _ => return Err(FsError::InvalidArgument),
        };
        drop(entry);

        self.runtime
            .block_on(async move { ops.write_file(&dir_id, &name, &content).await })
            .map_err(|e| FsError::from(e))?;

        // Invalidate cache
        self.attr_cache.invalidate(&item_id);

        Ok(())
    }

    /// Reclaims an item, allowing its ID to be reused.
    pub fn reclaim(&self, item_id: u64) {
        if item_id == ROOT_ITEM_ID {
            return;
        }

        self.items.remove_by_id(item_id);
        self.attr_cache.invalidate(&item_id);
    }

    // ========================================================================
    // Helper methods
    // ========================================================================

    /// Gets file size with caching.
    fn get_file_size_cached(&self, item_id: u64, kind: &ItemKind) -> Result<u64, FsError> {
        // Check cache first
        if let Some(cached) = self.attr_cache.get(&item_id) {
            return Ok(cached.value.size);
        }

        let (dir_id, name) = match kind {
            ItemKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            _ => return Ok(0),
        };

        let ops = Arc::clone(&self.ops);

        // Get file info using find_file which includes encrypted_size
        let file_info = self
            .runtime
            .block_on(async move { ops.find_file(&dir_id, &name).await })
            .map_err(|e| {
                warn!("Failed to find file: {e}");
                FsError::from(e)
            })?;

        let encrypted_size = file_info.map(|info| info.encrypted_size).unwrap_or(0);
        let size = encrypted_to_plaintext_size_or_zero(encrypted_size);

        // Cache the result
        self.attr_cache.insert(
            item_id,
            CachedAttr {
                file_type: FileType::Regular,
                size,
            },
        );

        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_item_id() {
        assert_eq!(ROOT_ITEM_ID, 2);
    }

    #[test]
    fn test_file_attributes_accessors() {
        let attrs = FileAttributes::new(1, FileType::Regular, 1024, 501, 20);
        assert_eq!(attrs.attr_item_id(), 1);
        assert_eq!(attrs.attr_size(), 1024);
        assert!(attrs.attr_is_file());
        assert!(!attrs.attr_is_directory());
        assert!(!attrs.attr_is_symlink());

        let dir_attrs = FileAttributes::new(2, FileType::Directory, 0, 501, 20);
        assert!(dir_attrs.attr_is_directory());
        assert!(!dir_attrs.attr_is_file());

        let symlink_attrs = FileAttributes::new(3, FileType::Symlink, 10, 501, 20);
        assert!(symlink_attrs.attr_is_symlink());
        assert!(!symlink_attrs.attr_is_file());
    }

    #[test]
    fn test_directory_entry_accessors() {
        let entry = DirectoryEntry::new("test.txt".to_string(), 5, FileType::Regular, 100);
        assert_eq!(entry.entry_name(), b"test.txt");
        assert_eq!(entry.entry_item_id(), 5);
        assert_eq!(entry.entry_size(), 100);
        assert!(entry.entry_is_file());
    }

    #[test]
    fn test_volume_statistics_accessors() {
        let stats = VolumeStatistics::new(1000, 400, 100, 50, 4096);
        assert_eq!(stats.stats_total_bytes(), 1000);
        assert_eq!(stats.stats_available_bytes(), 400);
        assert_eq!(stats.stats_used_bytes(), 600);
        assert_eq!(stats.stats_total_inodes(), 100);
        assert_eq!(stats.stats_available_inodes(), 50);
        assert_eq!(stats.stats_block_size(), 4096);
    }
}
