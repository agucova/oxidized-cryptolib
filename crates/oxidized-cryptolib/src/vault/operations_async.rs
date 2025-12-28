//! Asynchronous vault operations for Cryptomator vaults.
//!
//! This module provides an async variant of [`VaultOperations`] for use with
//! Tokio. Filesystem operations use `tokio::fs`; cryptographic operations remain
//! synchronous (CPU-bound, fast).
//!
//! # Architecture
//!
//! `VaultOperationsAsync` delegates pure operations (path calculation, encryption,
//! decryption) to [`VaultCore`], sharing this logic with the
//! sync implementation. I/O uses `tokio::fs`, and file access is protected by
//! [`VaultLockManager`] for concurrent safety.
//!
//! # Key Methods
//!
//! - **Listing**: [`list_files`](VaultOperationsAsync::list_files), [`list_directories`](VaultOperationsAsync::list_directories)
//! - **Lookup**: [`find_file`](VaultOperationsAsync::find_file), [`find_directory`](VaultOperationsAsync::find_directory) - O(1) lookups by name
//! - **Read/Write**: [`read_file`](VaultOperationsAsync::read_file), [`write_file`](VaultOperationsAsync::write_file)
//! - **Streaming**: [`open_file`](VaultOperationsAsync::open_file), [`create_file`](VaultOperationsAsync::create_file) - for large files
//! - **Directories**: [`create_directory`](VaultOperationsAsync::create_directory), [`delete_directory`](VaultOperationsAsync::delete_directory)
//! - **Path resolution**: [`resolve_path`](VaultOperationsAsync::resolve_path)
//!
//! # Concurrency
//!
//! `VaultOperationsAsync` is `Send`, so it can be moved into spawned tasks:
//!
//! ```ignore
//! tokio::spawn(async move { ops.list_files(&root).await });
//! ```
//!
//! For concurrent operations in the same task, use `tokio::join!`:
//!
//! ```ignore
//! let (files, dirs) = tokio::join!(
//!     ops.list_files(&root),
//!     ops.list_directories(&root),
//! );
//! ```

use crate::{
    crypto::keys::MasterKey,
    fs::file::DecryptedFile,
    fs::file_async::decrypt_file_with_context_async,
    fs::name::{create_c9s_filename, decrypt_filename, encrypt_filename},
    fs::streaming::{VaultFileReader, VaultFileWriter},
    fs::symlink::{decrypt_symlink_target, encrypt_symlink_target},
    vault::config::{extract_master_key, validate_vault_claims, CipherCombo, VaultError},
    vault::handles::VaultHandleTable,
    vault::locks::{VaultLockManager, VaultLockRegistry},
    vault::ops::{calculate_directory_lookup_paths, calculate_file_lookup_paths, VaultCore},
    vault::path::{DirId, VaultPath},
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tracing::{debug, info, instrument, trace, warn};

pub use super::operations::{
    DirEntry, VaultDirectoryInfo, VaultFileInfo, VaultOpContext, VaultOperationError,
    VaultSymlinkInfo, VaultWriteError, DEFAULT_SHORTENING_THRESHOLD,
};
use super::operations::VaultOperations;
use super::path::EntryType;

/// Async-specific errors that can occur during vault operations.
#[derive(Error, Debug)]
pub enum AsyncVaultError {
    /// An error from the underlying vault operations
    #[error(transparent)]
    VaultOperation(Box<VaultOperationError>),
}

impl From<VaultOperationError> for AsyncVaultError {
    fn from(e: VaultOperationError) -> Self {
        AsyncVaultError::VaultOperation(Box::new(e))
    }
}

/// Asynchronous interface for vault operations.
///
/// Provides the same functionality as [`VaultOperations`] with async methods.
/// The `MasterKey` is stored in an `Arc` for efficient sharing across threads.
///
/// # Thread Safety
///
/// `VaultOperationsAsync` is both `Send` and `Sync`. For concurrent access from
/// multiple tasks, wrap the instance in `Arc`:
///
/// ```ignore
/// let ops = Arc::new(VaultOperationsAsync::open(&vault_path, "password")?);
/// let ops1 = Arc::clone(&ops);
/// let ops2 = Arc::clone(&ops);
///
/// tokio::join!(
///     async move { ops1.read_file(&dir_id, "file1.txt").await },
///     async move { ops2.read_file(&dir_id, "file2.txt").await },
/// );
/// ```
///
/// Or use the convenience method [`into_shared()`](Self::into_shared).
///
/// # Locking
///
/// All operations automatically acquire appropriate locks:
/// - Read operations (list, read): shared read locks
/// - Write operations (write, delete): exclusive write locks
/// - Multi-resource operations (move, rename): ordered locking to prevent deadlocks
pub struct VaultOperationsAsync {
    /// Core vault state and pure operations (shared with sync implementation).
    core: VaultCore,
    /// The master key wrapped in Arc for async sharing.
    master_key: Arc<MasterKey>,
    /// Lock manager for concurrent access (shared across instances).
    lock_manager: Arc<VaultLockManager>,
    /// Handle table for tracking open files (shared across instances).
    handle_table: Arc<VaultHandleTable>,
}

impl VaultOperationsAsync {
    /// Open an existing vault with the given password.
    ///
    /// This is the recommended way to open a vault. It reads the vault configuration,
    /// extracts the master key, and automatically configures the correct cipher combo
    /// and shortening threshold based on the vault's settings.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault root directory
    /// * `password` - The vault password
    ///
    /// # Errors
    ///
    /// Returns `VaultError` if:
    /// - The vault configuration cannot be read
    /// - The password is incorrect
    /// - The vault format is unsupported
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ops = VaultOperationsAsync::open(Path::new("my_vault"), "password")?;
    /// let files = ops.list_files(&DirId::root()).await?;
    /// ```
    #[instrument(level = "info", skip(password), fields(vault_path = %vault_path.display()))]
    pub fn open(vault_path: &Path, password: &str) -> Result<Self, VaultError> {
        // Extract master key (validates password)
        let master_key = extract_master_key(vault_path, password)?;

        // Read and validate vault config to get cipher combo and shortening threshold
        let vault_config_path = vault_path.join("vault.cryptomator");
        let vault_config_jwt = std::fs::read_to_string(&vault_config_path)?;
        let claims = validate_vault_claims(&vault_config_jwt, &master_key)?;

        let cipher_combo = claims.cipher_combo().expect("cipher combo already validated");
        let shortening_threshold = claims.shortening_threshold();

        info!(
            cipher_combo = ?cipher_combo,
            shortening_threshold = shortening_threshold,
            "Vault opened successfully"
        );

        Ok(Self::with_options_arc(
            vault_path,
            Arc::new(master_key),
            shortening_threshold,
            cipher_combo,
        ))
    }

    /// Create a new async vault operations instance with default SIV_GCM cipher.
    ///
    /// **Note:** Prefer [`open()`](Self::open) for opening existing vaults, as it
    /// automatically reads the correct cipher combo from the vault configuration.
    /// Use this method only when you need manual control over the configuration.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault root directory
    /// * `master_key` - The master key for encryption/decryption (will be wrapped in Arc)
    #[instrument(level = "info", skip(master_key), fields(vault_path = %vault_path.display()))]
    pub fn new(vault_path: &Path, master_key: Arc<MasterKey>) -> Self {
        Self::with_options_arc(vault_path, master_key, DEFAULT_SHORTENING_THRESHOLD, CipherCombo::SivGcm)
    }

    /// Create a new async vault operations instance with a custom shortening threshold.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault root directory
    /// * `master_key` - The master key for encryption/decryption (will be wrapped in Arc)
    /// * `shortening_threshold` - Maximum length for encrypted filenames before shortening
    #[instrument(level = "info", skip(master_key), fields(vault_path = %vault_path.display(), shortening_threshold = shortening_threshold))]
    pub fn with_shortening_threshold(
        vault_path: &Path,
        master_key: Arc<MasterKey>,
        shortening_threshold: usize,
    ) -> Self {
        Self::with_options_arc(vault_path, master_key, shortening_threshold, CipherCombo::SivGcm)
    }

    /// Create a new async vault operations instance with full configuration.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault root directory
    /// * `master_key` - The master key for encryption/decryption (will be wrapped in Arc)
    /// * `shortening_threshold` - Maximum length for encrypted filenames before shortening
    /// * `cipher_combo` - The cipher combination used by this vault (SIV_GCM or SIV_CTRMAC)
    #[instrument(level = "info", skip(master_key), fields(vault_path = %vault_path.display(), shortening_threshold = shortening_threshold, cipher_combo = ?cipher_combo))]
    pub fn with_options(
        vault_path: &Path,
        master_key: Arc<MasterKey>,
        shortening_threshold: usize,
        cipher_combo: CipherCombo,
    ) -> Self {
        Self::with_options_arc(vault_path, master_key, shortening_threshold, cipher_combo)
    }

    /// Internal constructor with Arc<MasterKey>.
    fn with_options_arc(
        vault_path: &Path,
        master_key: Arc<MasterKey>,
        shortening_threshold: usize,
        cipher_combo: CipherCombo,
    ) -> Self {
        info!("Initializing VaultOperationsAsync");
        // Use the global registry to get a shared lock manager for this vault path.
        // This ensures multiple instances operating on the same vault share locks.
        let lock_manager = VaultLockRegistry::global().get_or_create(vault_path);
        Self {
            core: VaultCore::with_shortening_threshold(
                vault_path.to_path_buf(),
                cipher_combo,
                shortening_threshold,
            ),
            master_key,
            lock_manager,
            handle_table: Arc::new(VaultHandleTable::new()),
        }
    }

    /// Create an async operations instance from an existing sync instance.
    ///
    /// This is useful when you already have a configured `VaultOperations` instance
    /// and want to use it in an async context. The cipher combo is preserved.
    ///
    /// The master key is cloned from the sync instance and wrapped in an Arc.
    ///
    /// # Arguments
    ///
    /// * `sync_ops` - The synchronous vault operations instance
    ///
    /// # Errors
    ///
    /// Returns an error if the master key cannot be cloned.
    #[instrument(level = "info", skip(sync_ops))]
    pub fn from_sync(sync_ops: &VaultOperations) -> Result<Self, crate::crypto::keys::KeyAccessError> {
        info!("Creating VaultOperationsAsync from sync instance");
        let cloned_key = Arc::new(sync_ops.master_key().try_clone()?);
        // Use the global registry to get a shared lock manager for this vault path.
        let lock_manager = VaultLockRegistry::global().get_or_create(sync_ops.vault_path());
        Ok(Self {
            core: VaultCore::with_shortening_threshold(
                sync_ops.vault_path().to_path_buf(),
                sync_ops.cipher_combo(),
                sync_ops.shortening_threshold(),
            ),
            master_key: cloned_key,
            lock_manager,
            handle_table: Arc::new(VaultHandleTable::new()),
        })
    }

    /// Convert this instance into an `Arc` for sharing across tasks.
    ///
    /// This is a convenience method for `Arc::new(self)`. For concurrent access
    /// from multiple tasks, wrap the instance in an Arc and clone it:
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ops = VaultOperationsAsync::open(&vault_path, "password")?.into_shared();
    /// let ops1 = Arc::clone(&ops);
    /// let ops2 = Arc::clone(&ops);
    ///
    /// // Both can be used concurrently
    /// tokio::join!(
    ///     async move { ops1.read_file(&dir_id, "file1.txt").await },
    ///     async move { ops2.read_file(&dir_id, "file2.txt").await },
    /// );
    /// ```
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Get a reference to the master key.
    ///
    /// Returns an `Arc` reference for efficient sharing.
    pub fn master_key(&self) -> &Arc<MasterKey> {
        &self.master_key
    }

    /// Get a reference to the lock manager.
    ///
    /// This is useful for advanced use cases where manual lock control is needed.
    pub fn lock_manager(&self) -> &Arc<VaultLockManager> {
        &self.lock_manager
    }

    /// Get a reference to the handle table.
    ///
    /// This is useful for FUSE implementations that need to track open file handles.
    pub fn handle_table(&self) -> &Arc<VaultHandleTable> {
        &self.handle_table
    }

    /// Returns the cipher combination used by this vault.
    pub fn cipher_combo(&self) -> CipherCombo {
        self.core.cipher_combo()
    }

    /// Returns a reference to the vault path.
    pub fn vault_path(&self) -> &Path {
        self.core.vault_path()
    }

    /// Returns the shortening threshold for encrypted filenames.
    pub fn shortening_threshold(&self) -> usize {
        self.core.shortening_threshold()
    }

    /// Calculate the storage path for a directory given its ID.
    ///
    /// This is a synchronous helper method since it only involves CPU-bound
    /// cryptographic hashing. Delegates to VaultCore.
    #[instrument(level = "trace", skip(self), fields(dir_id = %dir_id.as_str()))]
    fn calculate_directory_storage_path(&self, dir_id: &DirId) -> Result<PathBuf, VaultOperationError> {
        self.core
            .calculate_directory_storage_path(dir_id, &self.master_key)
            .map_err(|e| VaultOperationError::InvalidVaultStructure {
                reason: e.to_string(),
                context: VaultOpContext::new().with_dir_id(dir_id.as_str()),
            })
    }

    /// List all files in a directory (by directory ID).
    ///
    /// Returns information about all regular files in the specified directory.
    /// Directories and symlinks are excluded from the results.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID to list files from
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory storage path cannot be calculated
    /// - Reading the directory fails
    /// - File metadata cannot be read
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub async fn list_files(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultFileInfo>, VaultOperationError> {
        // Acquire directory read lock
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Acquired directory read lock for list_files");
        self.list_files_unlocked(directory_id).await
    }

    /// Internal implementation of list_files without locking.
    /// Called by other operations that already hold the necessary locks.
    async fn list_files_unlocked(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultFileInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id)?;
        trace!(path = %dir_path.display(), "Calculated storage path for list_files");

        // Check if directory exists using async fs
        match fs::metadata(&dir_path).await {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(VaultOperationError::InvalidVaultStructure {
                    reason: "Expected directory but found file".to_string(),
                    context: VaultOpContext::new()
                        .with_dir_id(directory_id.as_str())
                        .with_encrypted_path(&dir_path),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!("Directory storage path does not exist, returning empty file list");
                return Ok(Vec::new());
            }
            Err(e) => {
                return Err(VaultOperationError::Io {
                    source: e,
                    context: VaultOpContext::new()
                        .with_dir_id(directory_id.as_str())
                        .with_encrypted_path(&dir_path),
                });
            }
        }

        // Phase 1: Collect all entries (async I/O only, no crypto)
        let mut regular_files: Vec<(PathBuf, String, u64)> = Vec::new(); // (path, encrypted_name, size)
        let mut shortened_paths: Vec<PathBuf> = Vec::new();
        let mut entries = fs::read_dir(&dir_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            // Skip special files
            if file_name == "dirid.c9r" {
                continue;
            }

            let file_type = entry.file_type().await?;

            // Skip .c9r directories (these are handled by list_directories)
            if file_type.is_dir() && file_name.ends_with(".c9r") {
                continue;
            }

            // Skip other directories that aren't .c9s
            if file_type.is_dir() && !file_name.ends_with(".c9s") {
                continue;
            }

            if file_name.ends_with(".c9r") {
                let metadata = fs::metadata(&path).await?;
                regular_files.push((path, file_name, metadata.len()));
            } else if file_name.ends_with(".c9s") && file_type.is_dir() {
                shortened_paths.push(path);
            }
        }

        // Phase 2: Decrypt regular filenames in spawn_blocking to avoid blocking async runtime
        let dir_id_str = directory_id.as_str().to_string();
        let master_key = Arc::clone(&self.master_key);

        let decrypted_regular = tokio::task::spawn_blocking(move || {
            regular_files
                .into_iter()
                .filter_map(|(path, encrypted_name, size)| {
                    match decrypt_filename(&encrypted_name, &dir_id_str, &master_key) {
                        Ok(decrypted_name) => Some(VaultFileInfo {
                            name: decrypted_name,
                            encrypted_name,
                            encrypted_path: path,
                            encrypted_size: size,
                            is_shortened: false,
                        }),
                        Err(e) => {
                            warn!(encrypted_name = %encrypted_name, error = %e, "Failed to decrypt filename");
                            None
                        }
                    }
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| VaultOperationError::Io {
            source: std::io::Error::other(format!("Filename decryption task failed: {e}")),
            context: VaultOpContext::new().with_dir_id(directory_id.as_str()),
        })?;

        // Phase 3: Handle shortened files (these have their own async I/O for reading name.c9s)
        let mut files = decrypted_regular;
        for path in shortened_paths {
            if let Ok(info) = self.read_shortened_file_info(&path, directory_id).await {
                files.push(info);
            }
        }

        debug!(file_count = files.len(), "Listed files in directory");
        Ok(files)
    }

    /// List all subdirectories in a directory (by directory ID).
    ///
    /// Returns information about all subdirectories in the specified directory.
    /// Regular files and symlinks are excluded from the results.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID to list subdirectories from
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory storage path cannot be calculated
    /// - Reading the directory fails
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub async fn list_directories(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultDirectoryInfo>, VaultOperationError> {
        // Acquire directory read lock
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Acquired directory read lock for list_directories");
        self.list_directories_unlocked(directory_id).await
    }

    /// Internal implementation of list_directories without locking.
    /// Called by other operations that already hold the necessary locks.
    async fn list_directories_unlocked(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultDirectoryInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id)?;
        trace!(path = %dir_path.display(), "Calculated storage path for list_directories");

        // Check if directory exists using async fs
        match fs::metadata(&dir_path).await {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(VaultOperationError::InvalidVaultStructure {
                    reason: "Expected directory but found file".to_string(),
                    context: VaultOpContext::new()
                        .with_dir_id(directory_id.as_str())
                        .with_encrypted_path(&dir_path),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!("Directory storage path does not exist, returning empty directory list");
                return Ok(Vec::new());
            }
            Err(e) => {
                return Err(VaultOperationError::Io {
                    source: e,
                    context: VaultOpContext::new()
                        .with_dir_id(directory_id.as_str())
                        .with_encrypted_path(&dir_path),
                });
            }
        }

        // Phase 1: Collect all directory entries and read their dir.c9r content (async I/O)
        // Regular directories: (path, encrypted_name, dir_id_content)
        let mut regular_dirs: Vec<(PathBuf, String, String)> = Vec::new();
        let mut shortened_paths: Vec<PathBuf> = Vec::new();
        let mut entries = fs::read_dir(&dir_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            let file_type = entry.file_type().await?;

            if file_type.is_dir() && file_name.ends_with(".c9r") {
                // This is a regular directory - read dir.c9r content
                trace!(encrypted_name = %file_name, "Processing directory entry");
                let dir_id_file = path.join("dir.c9r");
                if let Ok(dir_id_content) = fs::read_to_string(&dir_id_file).await {
                    regular_dirs.push((path, file_name, dir_id_content));
                }
            } else if file_type.is_dir() && file_name.ends_with(".c9s") {
                // This might be a shortened directory - check for dir.c9r marker
                trace!(shortened_name = %file_name, "Processing shortened directory entry");
                let dir_c9r_path = path.join("dir.c9r");
                if fs::metadata(&dir_c9r_path).await.is_ok() {
                    shortened_paths.push(path);
                }
            }
        }

        // Phase 2: Decrypt regular directory names in spawn_blocking
        let dir_id_str = directory_id.as_str().to_string();
        let parent_dir_id = directory_id.clone();
        let master_key = Arc::clone(&self.master_key);

        let decrypted_regular = tokio::task::spawn_blocking(move || {
            regular_dirs
                .into_iter()
                .filter_map(|(path, encrypted_name, dir_id_content)| {
                    match decrypt_filename(&encrypted_name, &dir_id_str, &master_key) {
                        Ok(decrypted_name) => Some(VaultDirectoryInfo {
                            name: decrypted_name,
                            directory_id: DirId::from_raw(dir_id_content.trim()),
                            encrypted_path: path,
                            parent_directory_id: parent_dir_id.clone(),
                        }),
                        Err(e) => {
                            warn!(encrypted_name = %encrypted_name, error = %e, "Failed to decrypt directory name");
                            None
                        }
                    }
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| VaultOperationError::Io {
            source: std::io::Error::other(format!("Directory name decryption task failed: {e}")),
            context: VaultOpContext::new().with_dir_id(directory_id.as_str()),
        })?;

        // Phase 3: Handle shortened directories (these have their own async I/O for reading name.c9s)
        let mut directories = decrypted_regular;
        for path in shortened_paths {
            if let Ok(dir_info) = self.read_shortened_directory_info(&path, directory_id).await {
                directories.push(dir_info);
            }
        }

        debug!(directory_count = directories.len(), "Listed subdirectories");
        Ok(directories)
    }

    // ==================== Optimized Single-Entry Lookups ====================

    /// Find a specific file by name without scanning the entire directory.
    ///
    /// This is significantly faster than `list_files()` for directories with many files,
    /// as it directly checks the expected encrypted path rather than iterating all entries.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory containing the file
    /// * `filename` - The cleartext filename to find
    ///
    /// # Returns
    ///
    /// `Some(VaultFileInfo)` if found, `None` if not found.
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), filename = %filename))]
    pub async fn find_file(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<Option<VaultFileInfo>, VaultOperationError> {
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Acquired directory read lock for find_file");
        self.find_file_unlocked(directory_id, filename).await
    }

    /// Internal implementation of find_file without locking.
    async fn find_file_unlocked(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<Option<VaultFileInfo>, VaultOperationError> {
        let storage_path = self.calculate_directory_storage_path(directory_id)?;

        // Encrypt the filename to get the expected path
        let encrypted_name = encrypt_filename(filename, directory_id.as_str(), &self.master_key)?;

        // Calculate paths using shared helper
        let paths = calculate_file_lookup_paths(
            &storage_path,
            &encrypted_name,
            self.core.shortening_threshold(),
        );

        // Perform async I/O to check if file exists
        match fs::metadata(&paths.content_path).await {
            Ok(metadata) if paths.is_shortened || metadata.is_file() => {
                trace!(path = %paths.content_path.display(), shortened = paths.is_shortened, "Found file");
                Ok(Some(VaultFileInfo {
                    name: filename.to_string(),
                    encrypted_name: paths.encrypted_name,
                    encrypted_path: paths.content_path,
                    encrypted_size: metadata.len(),
                    is_shortened: paths.is_shortened,
                }))
            }
            Ok(_) => {
                // It's a directory, not a file (only possible for non-shortened paths)
                trace!("Path exists but is not a file (likely a directory)");
                Ok(None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                trace!(shortened = paths.is_shortened, "File not found");
                Ok(None)
            }
            Err(e) => Err(VaultOperationError::Io {
                source: e,
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str())
                    .with_encrypted_path(&paths.content_path),
            }),
        }
    }

    /// Find a specific directory by name without scanning the entire parent directory.
    ///
    /// This is significantly faster than `list_directories()` for directories with many entries,
    /// as it directly checks the expected encrypted path rather than iterating all entries.
    ///
    /// # Arguments
    ///
    /// * `parent_directory_id` - The parent directory
    /// * `dir_name` - The cleartext directory name to find
    ///
    /// # Returns
    ///
    /// `Some(VaultDirectoryInfo)` if found, `None` if not found.
    #[instrument(level = "debug", skip(self), fields(parent_dir_id = %parent_directory_id.as_str(), dir_name = %dir_name))]
    pub async fn find_directory(
        &self,
        parent_directory_id: &DirId,
        dir_name: &str,
    ) -> Result<Option<VaultDirectoryInfo>, VaultOperationError> {
        let _guard = self.lock_manager.directory_read(parent_directory_id).await;
        trace!("Acquired directory read lock for find_directory");
        self.find_directory_unlocked(parent_directory_id, dir_name).await
    }

    /// Internal implementation of find_directory without locking.
    async fn find_directory_unlocked(
        &self,
        parent_directory_id: &DirId,
        dir_name: &str,
    ) -> Result<Option<VaultDirectoryInfo>, VaultOperationError> {
        let storage_path = self.calculate_directory_storage_path(parent_directory_id)?;

        // Encrypt the directory name to get the expected path
        let encrypted_name = encrypt_filename(dir_name, parent_directory_id.as_str(), &self.master_key)?;

        // Calculate paths using shared helper
        let paths = calculate_directory_lookup_paths(
            &storage_path,
            &encrypted_name,
            self.core.shortening_threshold(),
        );

        // Perform async I/O to read directory ID from dir.c9r marker
        match fs::read_to_string(&paths.content_path).await {
            Ok(dir_id_content) => {
                let directory_id = DirId::from_raw(dir_id_content.trim());
                trace!(dir_id = %directory_id.as_str(), shortened = paths.is_shortened, "Found directory");
                Ok(Some(VaultDirectoryInfo {
                    name: dir_name.to_string(),
                    directory_id,
                    encrypted_path: paths.entry_path,
                    parent_directory_id: parent_directory_id.clone(),
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                trace!(shortened = paths.is_shortened, "Directory not found");
                Ok(None)
            }
            Err(e) => Err(VaultOperationError::Io {
                source: e,
                context: VaultOpContext::new()
                    .with_filename(dir_name)
                    .with_dir_id(parent_directory_id.as_str())
                    .with_encrypted_path(&paths.content_path),
            }),
        }
    }

    /// List all files and directories in a single operation.
    ///
    /// More efficient than calling `list_files()` and `list_directories()` separately,
    /// as it only acquires the lock once and iterates the directory once.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory to list
    ///
    /// # Returns
    ///
    /// A tuple of (files, directories).
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub async fn list_entries(
        &self,
        directory_id: &DirId,
    ) -> Result<(Vec<VaultFileInfo>, Vec<VaultDirectoryInfo>), VaultOperationError> {
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Acquired directory read lock for list_entries");

        let files = self.list_files_unlocked(directory_id).await?;
        let directories = self.list_directories_unlocked(directory_id).await?;

        debug!(file_count = files.len(), dir_count = directories.len(), "Listed all entries");
        Ok((files, directories))
    }

    /// List all files, directories, and symlinks in a single operation.
    ///
    /// This is the most efficient way to list all directory contents, as it acquires
    /// the lock once and runs all three listing operations concurrently.
    ///
    /// Designed for FUSE `readdir`/`readdirplus` and `lookup` operations which need
    /// to search across all entry types.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory to list
    ///
    /// # Returns
    ///
    /// A tuple of (files, directories, symlinks).
    #[allow(clippy::type_complexity)] // Return tuple is self-documenting
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub async fn list_all(
        &self,
        directory_id: &DirId,
    ) -> Result<(Vec<VaultFileInfo>, Vec<VaultDirectoryInfo>, Vec<VaultSymlinkInfo>), VaultOperationError> {
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Acquired directory read lock for list_all");

        // Run all three listings concurrently - they're all read-only directory scans
        let (files_result, dirs_result, symlinks_result) = tokio::join!(
            self.list_files_unlocked(directory_id),
            self.list_directories_unlocked(directory_id),
            self.list_symlinks_unlocked(directory_id)
        );

        let files = files_result?;
        let directories = dirs_result?;
        let symlinks = symlinks_result?;

        debug!(
            file_count = files.len(),
            dir_count = directories.len(),
            symlink_count = symlinks.len(),
            "Listed all entries"
        );
        Ok((files, directories, symlinks))
    }

    /// Read and decrypt a file by name within a directory.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory containing the file
    /// * `filename` - The cleartext filename to read
    ///
    /// # Returns
    ///
    /// The decrypted file contents.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file is not found in the directory
    /// - Decryption fails
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), filename = %filename))]
    pub async fn read_file(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<DecryptedFile, VaultOperationError> {
        // Acquire locks in consistent order: directory first, then file
        // This prevents deadlocks with write operations that use the same order
        let _dir_guard = self.lock_manager.directory_read(directory_id).await;
        let _file_guard = self.lock_manager.file_read(directory_id, filename).await;
        trace!("Acquired directory and file read locks for read_file");

        // Use optimized lookup instead of listing all files
        let file_info = self.find_file_unlocked(directory_id, filename).await?.ok_or_else(|| {
            warn!("File not found in directory");
            VaultOperationError::FileNotFound {
                filename: filename.to_string(),
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str()),
            }
        })?;

        debug!(encrypted_path = %file_info.encrypted_path.display(), "Found file, decrypting");

        // Decrypt the file using async file reading
        let decrypted = decrypt_file_with_context_async(
            &file_info.encrypted_path,
            &self.master_key,
            Some(filename),
            Some(directory_id.as_str()),
        )
        .await?;

        info!(filename = %filename, content_size = decrypted.content.len(), "File decrypted successfully");
        Ok(decrypted)
    }

    // ==================== Streaming Operations ====================

    /// Open a file for streaming reads.
    ///
    /// Returns a [`VaultFileReader`] that supports random-access reads without
    /// loading the entire file into memory. Ideal for FUSE `read(offset, size)` operations.
    ///
    /// # Lock Lifetime
    ///
    /// The returned [`VaultFileReader`] holds the directory and file read locks for its
    /// entire lifetime. The locks are automatically released when the reader is dropped.
    /// This ensures consistent reads even if concurrent writes occur, but means you should
    /// drop the reader promptly when done to avoid blocking writers.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory containing the file
    /// * `filename` - The cleartext filename to open
    ///
    /// # Returns
    ///
    /// A [`VaultFileReader`] for efficient random-access reads.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut reader = ops.open_file(&dir_id, "large_file.bin").await?;
    ///
    /// // Read 1KB starting at offset 1MB
    /// let data = reader.read_range(1024 * 1024, 1024).await?;
    ///
    /// // IMPORTANT: Drop reader when done to release locks
    /// drop(reader);
    /// ```
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), filename = %filename))]
    pub async fn open_file(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<VaultFileReader, VaultOperationError> {
        debug!("Opening file for streaming read");

        // Acquire locks in consistent order: directory first, then file
        // These locks will be transferred to the reader to hold for its lifetime
        let dir_guard = self.lock_manager.directory_read(directory_id).await;
        let file_guard = self.lock_manager.file_read(directory_id, filename).await;
        trace!("Acquired directory and file read locks for open_file");

        // Use optimized lookup instead of listing all files
        let file_info = self.find_file_unlocked(directory_id, filename).await?.ok_or_else(|| {
            warn!("File not found in directory");
            VaultOperationError::FileNotFound {
                filename: filename.to_string(),
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str()),
            }
        })?;

        debug!(encrypted_path = %file_info.encrypted_path.display(), cipher_combo = ?self.core.cipher_combo(), "Found file, opening for streaming");

        // Open the file using VaultFileReader with the vault's cipher combo
        let reader = VaultFileReader::open_with_cipher(
            &file_info.encrypted_path,
            &self.master_key,
            self.core.cipher_combo(),
        )
            .await
            .map_err(|e| VaultOperationError::Streaming {
                source: Box::new(e),
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str())
                    .with_encrypted_path(&file_info.encrypted_path),
            })?;

        // Transfer the lock guards to the reader so they're held for its lifetime
        let reader = reader.with_locks(dir_guard, file_guard);

        info!(
            filename = %filename,
            plaintext_size = reader.plaintext_size(),
            has_locks = reader.has_locks(),
            "File opened for streaming with locks"
        );
        Ok(reader)
    }

    /// Open a file for streaming reads by path.
    ///
    /// Convenience wrapper around [`open_file()`] that accepts a path string.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub async fn open_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<VaultFileReader, VaultOperationError> {
        let (dir_id, filename) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(dir_id = %dir_id, filename = %filename, "Resolved path for open");
        self.open_file(&dir_id, &filename).await
    }

    /// Create a file for streaming writes.
    ///
    /// Returns a [`VaultFileWriter`] for efficient streaming writes. Data is
    /// buffered and encrypted in 32KB chunks. Call `finish()` to atomically
    /// commit the file, or `abort()` to discard.
    ///
    /// # Lock Lifetime
    ///
    /// The returned [`VaultFileWriter`] holds the directory and file write locks for its
    /// entire lifetime. The locks are automatically released when:
    /// - `finish()` completes successfully
    /// - `abort()` is called
    /// - The writer is dropped
    ///
    /// This ensures exclusive access during writes, but means you should complete
    /// the write operation promptly to avoid blocking other operations.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory to create the file in
    /// * `filename` - The cleartext filename to create
    ///
    /// # Returns
    ///
    /// A [`VaultFileWriter`] for streaming writes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut writer = ops.create_file(&dir_id, "new_file.txt").await?;
    ///
    /// writer.write(b"Hello, ").await?;
    /// writer.write(b"World!").await?;
    ///
    /// // finish() releases the locks after committing the file
    /// let final_path = writer.finish().await?;
    /// ```
    #[instrument(level = "info", skip(self), fields(dir_id = %directory_id.as_str(), filename = %filename))]
    pub async fn create_file(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<VaultFileWriter, VaultWriteError> {
        info!("Creating file for streaming write");

        // Acquire locks in consistent order: directory first, then file
        // These locks will be transferred to the writer to hold for its lifetime
        let dir_guard = self.lock_manager.directory_write(directory_id).await;
        let file_guard = self.lock_manager.file_write(directory_id, filename).await;
        trace!("Acquired directory and file write locks for create_file");

        // Calculate storage path for this directory
        let storage_path = self.calculate_directory_storage_path(directory_id)?;
        trace!(storage_path = %storage_path.display(), "Calculated storage path");

        // Ensure storage directory exists
        fs::create_dir_all(&storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&storage_path),
        })?;

        // Encrypt the filename
        debug!("Encrypting filename");
        let encrypted_name = encrypt_filename(filename, directory_id.as_str(), &self.master_key)?;

        // Determine destination path (handle long filenames)
        let is_shortened = encrypted_name.len() > self.core.shortening_threshold();
        let dest_path = if is_shortened {
            trace!("Using shortened filename format (.c9s)");
            let hash = create_c9s_filename(&encrypted_name);
            let short_dir = storage_path.join(format!("{hash}.c9s"));

            // Create the .c9s directory and write name.c9s
            fs::create_dir_all(&short_dir).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&short_dir),
            })?;
            self.safe_write(&short_dir.join("name.c9s"), encrypted_name.as_bytes()).await?;

            short_dir.join("contents.c9r")
        } else {
            storage_path.join(format!("{encrypted_name}.c9r"))
        };

        // Create the streaming writer
        let writer = VaultFileWriter::create(&dest_path, &self.master_key)
            .await
            .map_err(|e| VaultWriteError::Streaming {
                source: Box::new(e),
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str())
                    .with_encrypted_path(&dest_path),
            })?;

        // Transfer the lock guards to the writer so they're held for its lifetime
        let writer = writer.with_locks(dir_guard, file_guard);

        info!(
            dest_path = %dest_path.display(),
            has_locks = writer.has_locks(),
            "File created for streaming write with locks"
        );
        Ok(writer)
    }

    /// Create a file for streaming writes by path.
    ///
    /// Convenience wrapper around [`create_file()`] that accepts a path string.
    /// Does NOT create parent directories automatically.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub async fn create_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<VaultFileWriter, VaultWriteError> {
        let (dir_id, filename) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(dir_id = %dir_id, filename = %filename, "Resolved path for create");
        self.create_file(&dir_id, &filename).await
    }

    // ==================== Write Operations ====================

    /// Write encrypted content to a file in the vault.
    ///
    /// # Arguments
    ///
    /// * `dir_id` - The directory to write the file in
    /// * `filename` - The cleartext filename
    /// * `content` - The content to encrypt and write
    ///
    /// # Returns
    ///
    /// The encrypted path where the file was written.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A file with this name already exists
    /// - Encryption fails
    /// - Writing the file fails
    #[instrument(level = "info", skip(self, content), fields(dir_id = %dir_id.as_str(), filename = %filename, content_size = content.len()))]
    pub async fn write_file(
        &self,
        dir_id: &DirId,
        filename: &str,
        content: &[u8],
    ) -> Result<PathBuf, VaultWriteError> {
        info!("Writing file to vault");

        // Acquire locks in consistent order: directory first, then file.
        //
        // Note: We always acquire the directory write lock even for overwrites. While we could
        // theoretically use only a file write lock for existing files, this would require:
        // 1. Checking existence with a read lock
        // 2. Releasing the read lock and acquiring write locks (TOCTOU race window)
        // 3. Handling the case where another task creates/deletes the file in between
        //
        // The current simple approach is correct and the write lock is held briefly (only during
        // the filesystem write, not during encryption). The slight contention overhead is worth
        // the simplicity and correctness guarantee.
        let _dir_guard = self.lock_manager.directory_write(dir_id).await;
        let _file_guard = self.lock_manager.file_write(dir_id, filename).await;
        trace!("Acquired directory and file write locks for write_file");

        // 1. Calculate storage path for this directory
        let storage_path = self.calculate_directory_storage_path(dir_id)?;
        trace!(storage_path = %storage_path.display(), "Calculated storage path");

        // 2. Ensure storage directory exists
        fs::create_dir_all(&storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&storage_path),
        })?;

        // 3. Encrypt the filename
        debug!("Encrypting filename");
        let encrypted_name = encrypt_filename(filename, dir_id.as_str(), &self.master_key)?;

        // 4-8. Encrypt file using the vault's cipher combo
        let file_data = self.core.cipher_combo().encrypt_file(content, &self.master_key)?;

        // 10. Determine file path and write (handle long filenames)
        let is_shortened = encrypted_name.len() > self.core.shortening_threshold();
        debug!(is_shortened = is_shortened, encrypted_size = file_data.len(), "Writing encrypted file");

        let file_path = if is_shortened {
            trace!("Using shortened filename format (.c9s)");
            self.write_shortened_file(&storage_path, &encrypted_name, &file_data).await?
        } else {
            let path = storage_path.join(format!("{encrypted_name}.c9r"));
            self.safe_write(&path, &file_data).await?;
            path
        };

        info!(encrypted_path = %file_path.display(), "File written successfully");
        Ok(file_path)
    }

    /// Write a file with a shortened name (.c9s format)
    async fn write_shortened_file(
        &self,
        storage_path: &Path,
        encrypted_name: &str,
        file_data: &[u8],
    ) -> Result<PathBuf, VaultWriteError> {
        let hash = create_c9s_filename(encrypted_name);
        let short_dir = storage_path.join(format!("{hash}.c9s"));
        fs::create_dir_all(&short_dir).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&short_dir),
        })?;

        // Write name.c9s (contains the original encrypted name)
        self.safe_write(&short_dir.join("name.c9s"), encrypted_name.as_bytes()).await?;

        // Write contents.c9r (contains the actual file data)
        let contents_path = short_dir.join("contents.c9r");
        self.safe_write(&contents_path, file_data).await?;

        Ok(contents_path)
    }

    /// Write data to a file, using atomic write pattern only for overwrites.
    ///
    /// - **New files**: Direct write (if it fails, nothing is lost)
    /// - **Existing files**: Temp file + rename (protects existing data from corruption)
    ///
    /// This matches the safety guarantees of a typical filesystem where overwrites
    /// risk data loss on failure, but new file creation does not.
    async fn safe_write(&self, path: &Path, data: &[u8]) -> Result<(), VaultWriteError> {
        let file_exists = fs::metadata(path).await.is_ok();

        if file_exists {
            // Overwrite: use atomic pattern to protect existing data
            let parent = path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: VaultOpContext::new().with_encrypted_path(path),
            })?;

            let temp_path = parent.join(format!(".tmp.{}", uuid::Uuid::new_v4()));

            // Write to temp file
            fs::write(&temp_path, data).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&temp_path),
            })?;

            // Atomic rename (if this fails, original file is still intact)
            if let Err(e) = fs::rename(&temp_path, path).await {
                // Best effort cleanup of temp file using async fs
                // We spawn this as a background task since we can't await in map_err
                let temp_path_clone = temp_path.clone();
                tokio::spawn(async move {
                    let _ = fs::remove_file(&temp_path_clone).await;
                });
                return Err(VaultWriteError::Io {
                    source: e,
                    context: VaultOpContext::new().with_encrypted_path(path),
                });
            }
        } else {
            // New file: direct write (no existing data at risk)
            fs::write(path, data).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(path),
            })?;
        }

        Ok(())
    }

    // ==================== Read Helpers ====================

    /// Read information about a shortened file (.c9s format).
    async fn read_shortened_file_info(
        &self,
        c9s_path: &Path,
        directory_id: &DirId,
    ) -> Result<VaultFileInfo, VaultOperationError> {
        let name_file = c9s_path.join("name.c9s");
        let contents_file = c9s_path.join("contents.c9r");

        // Read the encrypted name from name.c9s
        let encrypted_name = fs::read_to_string(&name_file).await.map_err(|e| VaultOperationError::Io {
            source: e,
            context: VaultOpContext::new()
                .with_dir_id(directory_id.as_str())
                .with_encrypted_path(&name_file),
        })?;

        // Decrypt the filename (synchronous, CPU-bound)
        let decrypted_name = decrypt_filename(&encrypted_name, directory_id.as_str(), &self.master_key)?;

        // Get file size
        let metadata = fs::metadata(&contents_file).await.map_err(|e| VaultOperationError::Io {
            source: e,
            context: VaultOpContext::new()
                .with_filename(&decrypted_name)
                .with_dir_id(directory_id.as_str())
                .with_encrypted_path(&contents_file),
        })?;

        Ok(VaultFileInfo {
            name: decrypted_name,
            encrypted_name,
            encrypted_path: contents_file,
            encrypted_size: metadata.len(),
            is_shortened: true,
        })
    }

    /// Read information about a shortened directory (.c9s format).
    async fn read_shortened_directory_info(
        &self,
        c9s_path: &Path,
        parent_directory_id: &DirId,
    ) -> Result<VaultDirectoryInfo, VaultOperationError> {
        let name_file = c9s_path.join("name.c9s");
        let dir_id_file = c9s_path.join("dir.c9r");

        // Read the encrypted name from name.c9s
        let encrypted_name = fs::read_to_string(&name_file).await.map_err(|e| VaultOperationError::Io {
            source: e,
            context: VaultOpContext::new()
                .with_dir_id(parent_directory_id.as_str())
                .with_encrypted_path(&name_file),
        })?;

        // Decrypt the directory name (synchronous, CPU-bound)
        let decrypted_name = decrypt_filename(&encrypted_name, parent_directory_id.as_str(), &self.master_key)?;

        // Read directory ID
        let dir_id_content = fs::read_to_string(&dir_id_file).await.map_err(|e| VaultOperationError::Io {
            source: e,
            context: VaultOpContext::new()
                .with_filename(&decrypted_name)
                .with_dir_id(parent_directory_id.as_str())
                .with_encrypted_path(&dir_id_file),
        })?;

        let directory_id = DirId::from_raw(dir_id_content.trim());

        Ok(VaultDirectoryInfo {
            name: decrypted_name,
            directory_id,
            encrypted_path: c9s_path.to_path_buf(),
            parent_directory_id: parent_directory_id.clone(),
        })
    }

    // ==================== Path Resolution ====================

    /// Resolve a path to its directory ID and determine if it's a directory.
    ///
    /// Walks the vault directory tree from root, resolving each path component.
    ///
    /// # Returns
    /// - For directories: `(directory_id, true)`
    /// - For files: `(parent_directory_id, false)`
    #[instrument(level = "debug", skip(self), fields(path = %path))]
    pub async fn resolve_path(&self, path: &str) -> Result<(DirId, bool), VaultOperationError> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        debug!(component_count = components.len(), "Resolving path");

        if components.is_empty() {
            debug!("Path is root directory");
            return Ok((DirId::root(), true));
        }

        let mut current_dir_id = DirId::root();
        let mut is_directory = true;

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            trace!(component = %component, depth = i, is_last = is_last, "Traversing path component");

            if is_last {
                // Check if it's a file using optimized lookup
                if self.find_file(&current_dir_id, component).await?.is_some() {
                    trace!("Found file at path");
                    is_directory = false;
                    break;
                }
            }

            // Look for directory using optimized lookup
            let dir = self.find_directory(&current_dir_id, component).await?.ok_or_else(|| {
                warn!(component = %component, "Directory not found during path resolution");
                VaultOperationError::DirectoryNotFound {
                    name: component.to_string(),
                    context: VaultOpContext::new()
                        .with_vault_path(path)
                        .with_dir_id(current_dir_id.as_str()),
                }
            })?;

            trace!(new_dir_id = %dir.directory_id.as_str(), "Descended into directory");
            current_dir_id = dir.directory_id;
        }

        debug!(resolved_dir_id = %current_dir_id.as_str(), is_directory = is_directory, "Path resolved");
        Ok((current_dir_id, is_directory))
    }

    /// Resolve a path to its parent directory ID and final component name.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub async fn resolve_parent_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<(DirId, String), VaultOperationError> {
        let vault_path = VaultPath::new(path.as_ref());

        let (parent_path, filename) = vault_path
            .split()
            .ok_or(VaultOperationError::EmptyPath)?;

        let parent_dir_id = if parent_path.is_root() {
            DirId::root()
        } else {
            let (dir_id, is_dir) = self.resolve_path(parent_path.as_str()).await?;
            if !is_dir {
                return Err(VaultOperationError::NotADirectory {
                    path: parent_path.to_string(),
                });
            }
            dir_id
        };

        Ok((parent_dir_id, filename.to_string()))
    }

    // ==================== Path-Based Read/Write ====================

    /// Read a file by its path.
    ///
    /// Convenience wrapper around `read_file()` that accepts a path string.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub async fn read_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<DecryptedFile, VaultOperationError> {
        let (dir_id, filename) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(dir_id = %dir_id, filename = %filename, "Resolved path for read");
        self.read_file(&dir_id, &filename).await
    }

    /// Write a file by its path.
    ///
    /// Convenience wrapper around `write_file()` that accepts a path string.
    /// Does NOT create parent directories automatically.
    #[instrument(level = "debug", skip(self, content), fields(path = path.as_ref(), content_len = content.len()))]
    pub async fn write_by_path(
        &self,
        path: impl AsRef<str>,
        content: &[u8],
    ) -> Result<PathBuf, VaultWriteError> {
        let (dir_id, filename) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(dir_id = %dir_id, filename = %filename, "Resolved path for write");
        self.write_file(&dir_id, &filename, content).await
    }

    // ==================== Directory Operations ====================

    /// Create a new directory in the vault.
    ///
    /// Creates a directory with a new random UUID as its directory ID.
    #[instrument(level = "info", skip(self), fields(parent_dir_id = %parent_dir_id.as_str(), name = %name))]
    pub async fn create_directory(
        &self,
        parent_dir_id: &DirId,
        name: &str,
    ) -> Result<DirId, VaultWriteError> {
        info!("Creating new directory in vault");

        // Acquire parent directory write lock
        let _parent_guard = self.lock_manager.directory_write(parent_dir_id).await;
        trace!("Acquired parent directory write lock for create_directory");

        // Calculate storage path for parent directory
        let parent_storage_path = self.calculate_directory_storage_path(parent_dir_id)?;
        trace!(parent_storage_path = %parent_storage_path.display(), "Calculated parent storage path");
        fs::create_dir_all(&parent_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&parent_storage_path),
        })?;

        // Generate a new directory ID (UUID)
        let dir_id_str = uuid::Uuid::new_v4().to_string();
        let dir_id = DirId::from_raw(&dir_id_str);
        debug!(new_dir_id = %dir_id_str, "Generated new directory ID");

        // Encrypt the directory name (CPU-bound, synchronous)
        let encrypted_name = encrypt_filename(name, parent_dir_id.as_str(), &self.master_key)?;

        // Create the encrypted directory structure
        if encrypted_name.len() > self.core.shortening_threshold() {
            self.create_shortened_directory(&parent_storage_path, &encrypted_name, &dir_id).await?;
        } else {
            let encrypted_dir_path = parent_storage_path.join(format!("{encrypted_name}.c9r"));
            fs::create_dir_all(&encrypted_dir_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&encrypted_dir_path),
            })?;
            self.safe_write(&encrypted_dir_path.join("dir.c9r"), dir_id.as_str().as_bytes()).await?;
        }

        // Create the storage directory for this new directory
        let new_storage_path = self.calculate_directory_storage_path(&dir_id)?;
        fs::create_dir_all(&new_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&new_storage_path),
        })?;

        // Write dirid.c9r backup file (using cipher combo for proper cipher selection)
        let encrypted_dir_id = self.core.cipher_combo().encrypt_dir_id_backup(dir_id.as_str(), &self.master_key)?;
        self.safe_write(&new_storage_path.join("dirid.c9r"), &encrypted_dir_id).await?;

        info!(created_dir_id = %dir_id.as_str(), "Directory created successfully");
        Ok(dir_id)
    }

    /// Create a shortened directory (.c9s format).
    async fn create_shortened_directory(
        &self,
        parent_storage_path: &Path,
        encrypted_name: &str,
        dir_id: &DirId,
    ) -> Result<PathBuf, VaultWriteError> {
        let hash = create_c9s_filename(encrypted_name);
        let short_dir = parent_storage_path.join(format!("{hash}.c9s"));
        fs::create_dir_all(&short_dir).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&short_dir),
        })?;

        self.safe_write(&short_dir.join("name.c9s"), encrypted_name.as_bytes()).await?;
        self.safe_write(&short_dir.join("dir.c9r"), dir_id.as_str().as_bytes()).await?;

        Ok(short_dir)
    }

    // ==================== Delete Operations ====================

    /// Delete a file from the vault.
    #[instrument(level = "info", skip(self), fields(dir_id = %dir_id.as_str(), filename = %filename))]
    pub async fn delete_file(&self, dir_id: &DirId, filename: &str) -> Result<(), VaultWriteError> {
        info!("Deleting file from vault");

        // Acquire directory write lock (for listing consistency) and file write lock
        // Order: directory first, then file
        let _dir_guard = self.lock_manager.directory_write(dir_id).await;
        let _file_guard = self.lock_manager.file_write(dir_id, filename).await;
        trace!("Acquired directory and file write locks for delete_file");

        let ctx = VaultOpContext::new()
            .with_filename(filename)
            .with_dir_id(dir_id.as_str());

        // Use optimized lookup instead of listing all files
        let file_info = self.find_file_unlocked(dir_id, filename).await.map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: ctx.clone(),
            },
        })?.ok_or_else(|| VaultWriteError::FileNotFound {
            filename: filename.to_string(),
            context: ctx.clone(),
        })?;

        debug!(is_shortened = file_info.is_shortened, encrypted_path = %file_info.encrypted_path.display(), "Removing encrypted file");

        if file_info.is_shortened {
            // Remove the entire .c9s directory
            let parent = file_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: ctx.clone().with_encrypted_path(&file_info.encrypted_path),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(parent),
            })?;
        } else {
            fs::remove_file(&file_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&file_info.encrypted_path),
            })?;
        }

        info!("File deleted successfully");
        Ok(())
    }

    /// Delete a directory from the vault (must be empty).
    #[instrument(level = "info", skip(self), fields(parent_dir_id = %parent_dir_id.as_str(), dir_name = %dir_name))]
    pub async fn delete_directory(
        &self,
        parent_dir_id: &DirId,
        dir_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Deleting directory from vault");

        // Acquire parent directory write lock first
        let _parent_guard = self.lock_manager.directory_write(parent_dir_id).await;
        trace!("Acquired parent directory write lock for delete_directory");

        let ctx = VaultOpContext::new()
            .with_filename(dir_name)
            .with_dir_id(parent_dir_id.as_str());

        // Use optimized lookup instead of listing all directories
        let dir_info = self.find_directory_unlocked(parent_dir_id, dir_name).await.map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: ctx.clone(),
            },
        })?.ok_or_else(|| VaultWriteError::DirectoryNotFound {
            name: dir_name.to_string(),
            context: ctx.clone(),
        })?;

        trace!(target_dir_id = %dir_info.directory_id.as_str(), "Found directory to delete");

        // Acquire target directory write lock (in addition to parent lock)
        let _target_guard = self.lock_manager.directory_write(&dir_info.directory_id).await;
        trace!("Acquired target directory write lock for delete_directory");

        // Check directory is empty (use unlocked versions since we hold both locks)
        let target_ctx = ctx.clone().with_dir_id(dir_info.directory_id.as_str());
        let files = self.list_files_unlocked(&dir_info.directory_id).await.map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: target_ctx.clone(),
            },
        })?;
        let subdirs = self.list_directories_unlocked(&dir_info.directory_id).await.map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: target_ctx.clone(),
            },
        })?;

        if !files.is_empty() || !subdirs.is_empty() {
            debug!(file_count = files.len(), subdir_count = subdirs.len(), "Cannot delete non-empty directory");
            return Err(VaultWriteError::DirectoryNotEmpty {
                context: target_ctx.with_encrypted_path(&dir_info.encrypted_path),
            });
        }

        // Remove the storage directory
        let storage_path = self.calculate_directory_storage_path(&dir_info.directory_id)?;
        if fs::metadata(&storage_path).await.is_ok() {
            fs::remove_dir_all(&storage_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&storage_path),
            })?;
        }

        // Remove the directory entry from parent
        if fs::metadata(&dir_info.encrypted_path).await.is_ok() {
            fs::remove_dir_all(&dir_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&dir_info.encrypted_path),
            })?;
        }

        info!("Directory deleted successfully");
        Ok(())
    }

    // ==================== Rename/Move Operations ====================

    /// Rename a file within a directory.
    ///
    /// Only changes filename encryption; file content is copied directly.
    #[instrument(level = "info", skip(self), fields(dir_id = %dir_id.as_str(), old_name = %old_name, new_name = %new_name))]
    pub async fn rename_file(
        &self,
        dir_id: &DirId,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Renaming file in vault");

        let ctx = VaultOpContext::new()
            .with_filename(old_name)
            .with_dir_id(dir_id.as_str());

        if old_name == new_name {
            debug!("Source and destination names are identical");
            return Err(VaultWriteError::SameSourceAndDestination { context: ctx });
        }

        // Acquire directory write lock and file write locks in order
        let _dir_guard = self.lock_manager.directory_write(dir_id).await;
        // Lock both files in alphabetical order to prevent deadlocks
        let _file_guards = self
            .lock_manager
            .lock_files_write_ordered(dir_id, &[old_name, new_name])
            .await;
        trace!("Acquired directory and file write locks for rename_file");

        // Use optimized lookup for source file
        let source_info = self.find_file_unlocked(dir_id, old_name).await?.ok_or_else(|| {
            VaultWriteError::FileNotFound {
                filename: old_name.to_string(),
                context: ctx.clone(),
            }
        })?;

        // Check target doesn't exist using optimized lookup
        if self.find_file_unlocked(dir_id, new_name).await?.is_some() {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: new_name.to_string(),
                context: ctx.clone().with_filename(new_name),
            });
        }

        let storage_path = self.calculate_directory_storage_path(dir_id)?;
        let new_encrypted_name = encrypt_filename(new_name, dir_id.as_str(), &self.master_key)?;
        let new_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Copy to new location first (crash-safe)
        // Use fs::copy for efficiency when both source and dest are regular files
        if new_is_long {
            // Shortened destination requires special directory structure
            let file_data = fs::read(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: ctx.clone().with_encrypted_path(&source_info.encrypted_path),
            })?;
            self.write_shortened_file(&storage_path, &new_encrypted_name, &file_data).await?;
        } else {
            let new_path = storage_path.join(format!("{new_encrypted_name}.c9r"));
            // Use fs::copy for efficient file copying (no memory allocation for large files)
            fs::copy(&source_info.encrypted_path, &new_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: ctx.clone().with_encrypted_path(&new_path),
            })?;
        }

        // Remove the old file
        if source_info.is_shortened {
            let parent = source_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: ctx.clone().with_encrypted_path(&source_info.encrypted_path),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(parent),
            })?;
        } else {
            fs::remove_file(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path),
            })?;
        }

        info!("File renamed successfully");
        Ok(())
    }

    /// Rename a directory.
    ///
    /// Changes the directory's name within its parent directory. The directory ID
    /// remains unchanged, only the encrypted directory entry is updated.
    ///
    /// # Arguments
    ///
    /// * `parent_dir_id` - The directory ID of the parent directory
    /// * `old_name` - Current name of the directory
    /// * `new_name` - New name for the directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source directory doesn't exist
    /// - A directory with the new name already exists
    /// - old_name equals new_name
    #[instrument(level = "info", skip(self), fields(parent_dir_id = %parent_dir_id.as_str(), old_name = %old_name, new_name = %new_name))]
    pub async fn rename_directory(
        &self,
        parent_dir_id: &DirId,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Renaming directory in vault");

        let ctx = VaultOpContext::new()
            .with_filename(old_name)
            .with_dir_id(parent_dir_id.as_str());

        // Fast path: no-op if names are identical
        if old_name == new_name {
            return Err(VaultWriteError::SameSourceAndDestination { context: ctx });
        }

        // Acquire parent directory write lock
        let _parent_guard = self.lock_manager.directory_write(parent_dir_id).await;
        trace!("Acquired parent directory write lock for rename_directory");

        // Find the source directory using optimized lookup
        let source_info = self
            .find_directory_unlocked(parent_dir_id, old_name)
            .await
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
                other => VaultWriteError::Io {
                    source: std::io::Error::other(other.to_string()),
                    context: ctx.clone(),
                },
            })?
            .ok_or_else(|| VaultWriteError::DirectoryNotFound {
                name: old_name.to_string(),
                context: ctx.clone(),
            })?;

        // Check that target doesn't exist using optimized lookup
        if self
            .find_directory_unlocked(parent_dir_id, new_name)
            .await?
            .is_some()
        {
            return Err(VaultWriteError::DirectoryAlreadyExists {
                name: new_name.to_string(),
                context: ctx.clone().with_filename(new_name),
            });
        }

        let parent_storage_path = self.calculate_directory_storage_path(parent_dir_id)?;

        // Encrypt the new directory name
        let new_encrypted_name = encrypt_filename(new_name, parent_dir_id.as_str(), &self.master_key)?;
        let new_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // The directory ID stays the same - we're just renaming the entry
        let dir_id = &source_info.directory_id;

        // Create new directory entry first (crash-safe)
        if new_is_long {
            self.create_shortened_directory(&parent_storage_path, &new_encrypted_name, dir_id)
                .await?;
        } else {
            let new_path = parent_storage_path.join(format!("{new_encrypted_name}.c9r"));
            fs::create_dir_all(&new_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&new_path),
            })?;
            self.safe_write(&new_path.join("dir.c9r"), dir_id.as_str().as_bytes())
                .await?;
        }

        // Remove the old directory entry (not the storage directory - that stays!)
        fs::remove_dir_all(&source_info.encrypted_path)
            .await
            .map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path),
            })?;

        info!("Directory renamed successfully");
        Ok(())
    }

    /// Move a file from one directory to another.
    ///
    /// Re-encrypts the filename (uses directory ID as associated data),
    /// but copies file content directly without decryption.
    #[instrument(level = "info", skip(self), fields(src_dir_id = %src_dir_id.as_str(), filename = %filename, dest_dir_id = %dest_dir_id.as_str()))]
    pub async fn move_file(
        &self,
        src_dir_id: &DirId,
        filename: &str,
        dest_dir_id: &DirId,
    ) -> Result<(), VaultWriteError> {
        info!("Moving file in vault");

        let src_ctx = VaultOpContext::new()
            .with_filename(filename)
            .with_dir_id(src_dir_id.as_str());

        if src_dir_id == dest_dir_id {
            return Err(VaultWriteError::SameSourceAndDestination { context: src_ctx });
        }

        // Acquire directory write locks in consistent order to prevent deadlocks
        let _dir_guards = self
            .lock_manager
            .lock_directories_write_ordered(&[src_dir_id, dest_dir_id])
            .await;
        // Also lock the file in both directories
        let _src_file_guard = self.lock_manager.file_write(src_dir_id, filename).await;
        let _dest_file_guard = self.lock_manager.file_write(dest_dir_id, filename).await;
        trace!("Acquired all locks for move_file");

        // Use optimized lookup for source file
        let source_info = self.find_file_unlocked(src_dir_id, filename).await?.ok_or_else(|| {
            VaultWriteError::FileNotFound {
                filename: filename.to_string(),
                context: src_ctx.clone(),
            }
        })?;

        // Check that target doesn't exist using optimized lookup
        if self.find_file_unlocked(dest_dir_id, filename).await?.is_some() {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: filename.to_string(),
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(dest_dir_id.as_str()),
            });
        }

        // Ensure destination directory exists
        let dest_storage_path = self.calculate_directory_storage_path(dest_dir_id)?;
        fs::create_dir_all(&dest_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&dest_storage_path),
        })?;

        // Read raw encrypted file data
        let file_data = fs::read(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: src_ctx.clone().with_encrypted_path(&source_info.encrypted_path),
        })?;

        // Encrypt filename with NEW directory ID
        let new_encrypted_name = encrypt_filename(filename, dest_dir_id.as_str(), &self.master_key)?;
        let dest_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Write to destination (create before delete for crash safety)
        if dest_is_long {
            self.write_shortened_file(&dest_storage_path, &new_encrypted_name, &file_data).await?;
        } else {
            let dest_path = dest_storage_path.join(format!("{new_encrypted_name}.c9r"));
            self.safe_write(&dest_path, &file_data).await?;
        }

        // Remove from source
        if source_info.is_shortened {
            let parent = source_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: src_ctx.clone().with_encrypted_path(&source_info.encrypted_path),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(parent),
            })?;
        } else {
            fs::remove_file(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path),
            })?;
        }

        info!("File moved successfully");
        Ok(())
    }

    /// Move and rename a file atomically.
    ///
    /// This combines move and rename into a single atomic operation, avoiding the
    /// race condition that would occur if move and rename were done separately.
    /// Re-encrypts the filename with the new directory ID and new name.
    ///
    /// # Arguments
    ///
    /// * `src_dir_id` - Source directory ID
    /// * `src_name` - Source filename
    /// * `dest_dir_id` - Destination directory ID
    /// * `dest_name` - Destination filename (can be different from source)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Source file not found
    /// - Destination file already exists
    /// - IO error during copy/delete
    #[instrument(level = "info", skip(self), fields(src_dir_id = %src_dir_id.as_str(), src_name = %src_name, dest_dir_id = %dest_dir_id.as_str(), dest_name = %dest_name))]
    pub async fn move_and_rename_file(
        &self,
        src_dir_id: &DirId,
        src_name: &str,
        dest_dir_id: &DirId,
        dest_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Moving and renaming file in vault");

        let src_ctx = VaultOpContext::new()
            .with_filename(src_name)
            .with_dir_id(src_dir_id.as_str());

        // Same directory and same name is a no-op
        if src_dir_id == dest_dir_id && src_name == dest_name {
            return Err(VaultWriteError::SameSourceAndDestination { context: src_ctx });
        }

        // Acquire directory write locks in consistent order to prevent deadlocks
        let _dir_guards = self
            .lock_manager
            .lock_directories_write_ordered(&[src_dir_id, dest_dir_id])
            .await;

        // Lock files in both directories (need all four combinations for safety)
        let _src_file_guard = self.lock_manager.file_write(src_dir_id, src_name).await;
        let _dest_file_guard = self.lock_manager.file_write(dest_dir_id, dest_name).await;
        trace!("Acquired all locks for move_and_rename_file");

        // Find source file
        let source_info = self.find_file_unlocked(src_dir_id, src_name).await?.ok_or_else(|| {
            VaultWriteError::FileNotFound {
                filename: src_name.to_string(),
                context: src_ctx.clone(),
            }
        })?;

        // Check that target doesn't exist
        if self.find_file_unlocked(dest_dir_id, dest_name).await?.is_some() {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: dest_name.to_string(),
                context: VaultOpContext::new()
                    .with_filename(dest_name)
                    .with_dir_id(dest_dir_id.as_str()),
            });
        }

        // Ensure destination directory exists
        let dest_storage_path = self.calculate_directory_storage_path(dest_dir_id)?;
        fs::create_dir_all(&dest_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(&dest_storage_path),
        })?;

        // Read raw encrypted file data
        let file_data = fs::read(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: src_ctx.clone().with_encrypted_path(&source_info.encrypted_path),
        })?;

        // Encrypt filename with NEW directory ID and NEW name
        let new_encrypted_name = encrypt_filename(dest_name, dest_dir_id.as_str(), &self.master_key)?;
        let dest_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Write to destination (create before delete for crash safety)
        if dest_is_long {
            self.write_shortened_file(&dest_storage_path, &new_encrypted_name, &file_data).await?;
        } else {
            let dest_path = dest_storage_path.join(format!("{new_encrypted_name}.c9r"));
            self.safe_write(&dest_path, &file_data).await?;
        }

        // Remove from source
        if source_info.is_shortened {
            let parent = source_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: src_ctx.clone().with_encrypted_path(&source_info.encrypted_path),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(parent),
            })?;
        } else {
            fs::remove_file(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path),
            })?;
        }

        info!("File moved and renamed successfully");
        Ok(())
    }

    // ==================== Symlink Operations ====================

    /// List all symlinks in a directory (by directory ID).
    ///
    /// Returns information about all symbolic links in the specified directory.
    /// Regular files and directories are excluded from the results.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID to list symlinks from
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory storage path cannot be calculated
    /// - Reading the directory fails
    /// - Symlink data cannot be read or decrypted
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub async fn list_symlinks(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultSymlinkInfo>, VaultOperationError> {
        // Acquire directory read lock
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Acquired directory read lock for list_symlinks");
        self.list_symlinks_unlocked(directory_id).await
    }

    /// List all entries in a directory (files, directories, symlinks).
    ///
    /// Returns a unified list of all entries as `DirEntry` enum variants.
    /// This is the async equivalent of `VaultOperations::list()`.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID to list entries from
    ///
    /// # Errors
    ///
    /// Returns an error if listing any entry type fails.
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub async fn list(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<DirEntry>, VaultOperationError> {
        let mut entries = Vec::new();

        // Collect files
        for file in self.list_files(directory_id).await? {
            entries.push(DirEntry::File(file));
        }

        // Collect directories
        for dir in self.list_directories(directory_id).await? {
            entries.push(DirEntry::Directory(dir));
        }

        // Collect symlinks
        for symlink in self.list_symlinks(directory_id).await? {
            entries.push(DirEntry::Symlink(symlink));
        }

        debug!(entry_count = entries.len(), "Listed all entries in directory");
        Ok(entries)
    }

    /// Internal implementation of list_symlinks without locking.
    async fn list_symlinks_unlocked(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultSymlinkInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id)?;
        trace!(path = %dir_path.display(), "Calculated storage path for list_symlinks");

        if !fs::try_exists(&dir_path).await.unwrap_or(false) {
            debug!("Directory storage path does not exist, returning empty symlink list");
            return Ok(Vec::new());
        }

        let mut symlinks = Vec::new();

        let mut entries = fs::read_dir(&dir_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            let metadata = match fs::metadata(&path).await {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_dir() && file_name.ends_with(".c9r") {
                // Check if this is a symlink (has symlink.c9r)
                let symlink_file = path.join("symlink.c9r");
                if fs::try_exists(&symlink_file).await.unwrap_or(false) {
                    trace!(encrypted_name = %file_name, "Processing symlink entry");
                    if let Ok(info) = self.read_symlink_info_async(&path, &file_name, directory_id, false).await {
                        symlinks.push(info);
                    }
                }
            } else if metadata.is_dir() && file_name.ends_with(".c9s") {
                // Check if this is a shortened symlink
                let symlink_file = path.join("symlink.c9r");
                if fs::try_exists(&symlink_file).await.unwrap_or(false) {
                    trace!(shortened_name = %file_name, "Processing shortened symlink entry");
                    if let Ok(info) = self.read_shortened_symlink_info_async(&path, directory_id).await {
                        symlinks.push(info);
                    }
                }
            }
        }

        debug!(symlink_count = symlinks.len(), "Listed symlinks in directory");
        Ok(symlinks)
    }

    /// Helper to read symlink info from a path.
    async fn read_symlink_info_async(
        &self,
        symlink_path: &Path,
        encrypted_name: &str,
        parent_dir_id: &DirId,
        is_shortened: bool,
    ) -> Result<VaultSymlinkInfo, VaultOperationError> {
        // Decrypt the filename
        let decrypted_name = decrypt_filename(encrypted_name, parent_dir_id.as_str(), &self.master_key)?;

        // Read and decrypt the symlink target
        let symlink_file = symlink_path.join("symlink.c9r");
        let encrypted_data = fs::read(&symlink_file).await.map_err(|_| {
            VaultOperationError::SymlinkNotFound {
                name: decrypted_name.clone(),
                context: VaultOpContext::new()
                    .with_encrypted_path(&symlink_file)
                    .with_dir_id(parent_dir_id.as_str()),
            }
        })?;
        let target = decrypt_symlink_target(&encrypted_data, &self.master_key)?;

        Ok(VaultSymlinkInfo {
            name: decrypted_name,
            target,
            encrypted_path: symlink_path.to_path_buf(),
            is_shortened,
        })
    }

    /// Helper to read shortened symlink info.
    async fn read_shortened_symlink_info_async(
        &self,
        symlink_path: &Path,
        parent_dir_id: &DirId,
    ) -> Result<VaultSymlinkInfo, VaultOperationError> {
        // Read the original encrypted name from name.c9s
        let name_file = symlink_path.join("name.c9s");
        let original_name = fs::read_to_string(&name_file)
            .await
            .map_err(|e| VaultOperationError::InvalidVaultStructure {
                reason: format!("Failed to read shortened name: {e}"),
                context: VaultOpContext::new()
                    .with_encrypted_path(symlink_path)
                    .with_dir_id(parent_dir_id.as_str()),
            })?
            .trim()
            .to_string();

        self.read_symlink_info_async(symlink_path, &original_name, parent_dir_id, true).await
    }

    /// Read a symlink's target by providing the directory ID and symlink name.
    ///
    /// Symlinks are stored as `.c9r` directories containing a `symlink.c9r` file,
    /// which holds the encrypted target path using file content encryption (AES-GCM).
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID containing the symlink
    /// * `name` - The decrypted name of the symlink
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The symlink doesn't exist
    /// - The symlink data cannot be decrypted
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), name = %name))]
    pub async fn read_symlink(
        &self,
        directory_id: &DirId,
        name: &str,
    ) -> Result<String, VaultOperationError> {
        // Acquire directory read lock
        let _guard = self.lock_manager.directory_read(directory_id).await;
        debug!("Looking up symlink in directory");

        // Calculate the directory storage path
        let dir_path = self.calculate_directory_storage_path(directory_id)?;

        // Encrypt the symlink name to find it on disk
        let encrypted_name = encrypt_filename(name, directory_id.as_str(), &self.master_key)?;
        let symlink_dir = dir_path.join(format!("{encrypted_name}.c9r"));

        if !fs::try_exists(&symlink_dir).await.unwrap_or(false) {
            // Try shortened name (.c9s format)
            let shortened_hash = create_c9s_filename(&encrypted_name);
            let shortened_dir = dir_path.join(format!("{shortened_hash}.c9s"));

            if fs::try_exists(&shortened_dir).await.unwrap_or(false) {
                let symlink_file = shortened_dir.join("symlink.c9r");
                if fs::try_exists(&symlink_file).await.unwrap_or(false) {
                    let encrypted_data = fs::read(&symlink_file).await?;
                    let target = decrypt_symlink_target(&encrypted_data, &self.master_key)?;
                    info!(target_len = target.len(), "Symlink target decrypted successfully");
                    return Ok(target);
                }
            }

            return Err(VaultOperationError::SymlinkNotFound {
                name: name.to_string(),
                context: VaultOpContext::new()
                    .with_filename(name)
                    .with_dir_id(directory_id.as_str()),
            });
        }

        let symlink_file = symlink_dir.join("symlink.c9r");
        if !fs::try_exists(&symlink_file).await.unwrap_or(false) {
            return Err(VaultOperationError::NotASymlink {
                path: name.to_string(),
            });
        }

        let encrypted_data = fs::read(&symlink_file).await?;
        let target = decrypt_symlink_target(&encrypted_data, &self.master_key)?;
        info!(target_len = target.len(), "Symlink target decrypted successfully");
        Ok(target)
    }

    /// Create a symlink in the vault.
    ///
    /// Creates a `.c9r` directory containing a `symlink.c9r` file with the
    /// encrypted target path.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID to create the symlink in
    /// * `name` - The decrypted name for the symlink
    /// * `target` - The target path the symlink should point to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory doesn't exist
    /// - A symlink with the same name already exists
    /// - Writing the symlink data fails
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), name = %name))]
    pub async fn create_symlink(
        &self,
        directory_id: &DirId,
        name: &str,
        target: &str,
    ) -> Result<(), VaultWriteError> {
        // Acquire directory write lock
        let _guard = self.lock_manager.directory_write(directory_id).await;
        debug!(target = %target, "Creating symlink");

        // Calculate the directory storage path
        let dir_path = self.calculate_directory_storage_path(directory_id)
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
                VaultOperationError::Filename(e) => VaultWriteError::Filename(e),
                VaultOperationError::InvalidVaultStructure { reason, context } => {
                    VaultWriteError::DirectoryNotFound {
                        name: reason,
                        context,
                    }
                }
                _ => VaultWriteError::DirectoryNotFound {
                    name: directory_id.as_str().to_string(),
                    context: VaultOpContext::new().with_dir_id(directory_id.as_str()),
                },
            })?;

        // Ensure storage directory exists
        fs::create_dir_all(&dir_path).await?;

        // Encrypt the symlink name
        let encrypted_name = encrypt_filename(name, directory_id.as_str(), &self.master_key)?;

        // Check if name is too long and needs shortening
        let (symlink_dir, is_shortened) = if encrypted_name.len() > self.core.shortening_threshold() {
            let shortened_hash = create_c9s_filename(&encrypted_name);
            (dir_path.join(format!("{shortened_hash}.c9s")), true)
        } else {
            (dir_path.join(format!("{encrypted_name}.c9r")), false)
        };

        // Check if already exists
        if fs::try_exists(&symlink_dir).await.unwrap_or(false) {
            return Err(VaultWriteError::SymlinkAlreadyExists {
                name: name.to_string(),
                context: VaultOpContext::new()
                    .with_filename(name)
                    .with_dir_id(directory_id.as_str()),
            });
        }

        // Create the symlink directory
        fs::create_dir_all(&symlink_dir).await?;

        // If shortened, write the name.c9s file
        if is_shortened {
            fs::write(symlink_dir.join("name.c9s"), &encrypted_name).await?;
        }

        // Encrypt and write the symlink target
        let encrypted_target = encrypt_symlink_target(target, &self.master_key)?;
        fs::write(symlink_dir.join("symlink.c9r"), &encrypted_target).await?;

        info!("Symlink created successfully");
        Ok(())
    }

    /// Delete a symlink from the vault.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID containing the symlink
    /// * `name` - The decrypted name of the symlink to delete
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The symlink doesn't exist
    /// - Deleting the symlink fails
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), name = %name))]
    pub async fn delete_symlink(
        &self,
        directory_id: &DirId,
        name: &str,
    ) -> Result<(), VaultWriteError> {
        // Acquire directory write lock
        let _guard = self.lock_manager.directory_write(directory_id).await;
        debug!("Deleting symlink");

        let dir_path = self.calculate_directory_storage_path(directory_id)
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
                VaultOperationError::Filename(e) => VaultWriteError::Filename(e),
                _ => VaultWriteError::DirectoryNotFound {
                    name: directory_id.as_str().to_string(),
                    context: VaultOpContext::new().with_dir_id(directory_id.as_str()),
                },
            })?;

        // Encrypt the symlink name to find it on disk
        let encrypted_name = encrypt_filename(name, directory_id.as_str(), &self.master_key)?;
        let symlink_dir = dir_path.join(format!("{encrypted_name}.c9r"));

        if fs::try_exists(&symlink_dir).await.unwrap_or(false)
            && fs::try_exists(symlink_dir.join("symlink.c9r")).await.unwrap_or(false)
        {
            fs::remove_dir_all(&symlink_dir).await?;
            info!("Symlink deleted successfully");
            return Ok(());
        }

        // Try shortened name
        let shortened_hash = create_c9s_filename(&encrypted_name);
        let shortened_dir = dir_path.join(format!("{shortened_hash}.c9s"));

        if fs::try_exists(&shortened_dir).await.unwrap_or(false)
            && fs::try_exists(shortened_dir.join("symlink.c9r")).await.unwrap_or(false)
        {
            fs::remove_dir_all(&shortened_dir).await?;
            info!("Shortened symlink deleted successfully");
            return Ok(());
        }

        Err(VaultWriteError::FileNotFound {
            filename: name.to_string(),
            context: VaultOpContext::new()
                .with_filename(name)
                .with_dir_id(directory_id.as_str()),
        })
    }

    // ==================== Path-Based Operations ====================

    /// Check what type of entry exists at a path.
    ///
    /// Returns `Some(EntryType)` if an entry exists, `None` if nothing exists at the path.
    /// This is the async equivalent of `VaultOperations::entry_type()`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path within the vault (e.g., "documents/file.txt")
    ///
    /// # Example
    ///
    /// ```ignore
    /// match ops.entry_type("documents/readme.txt").await {
    ///     Some(EntryType::File) => println!("It's a file"),
    ///     Some(EntryType::Directory) => println!("It's a directory"),
    ///     Some(EntryType::Symlink) => println!("It's a symlink"),
    ///     None => println!("Nothing exists at this path"),
    /// }
    /// ```
    #[instrument(level = "trace", skip(self), fields(path = %path.as_ref()))]
    pub async fn entry_type(&self, path: impl AsRef<str>) -> Option<EntryType> {
        let vault_path = VaultPath::new(path.as_ref());

        if vault_path.is_root() {
            return Some(EntryType::Directory);
        }

        let (parent_path, entry_name) = vault_path.split()?;

        // Resolve parent directory to get its DirId
        let parent_dir_id = if parent_path.is_root() {
            DirId::root()
        } else {
            match self.resolve_path(parent_path.as_str()).await {
                Ok((dir_id, true)) => dir_id,
                _ => return None,
            }
        };

        // Check for symlink first (symlinks are the least common)
        if let Ok(symlinks) = self.list_symlinks(&parent_dir_id).await
            && symlinks.iter().any(|s| s.name == entry_name) {
                return Some(EntryType::Symlink);
            }

        // Check for directory
        if let Ok(dirs) = self.list_directories(&parent_dir_id).await
            && dirs.iter().any(|d| d.name == entry_name) {
                return Some(EntryType::Directory);
            }

        // Check for file
        if let Ok(files) = self.list_files(&parent_dir_id).await
            && files.iter().any(|f| f.name == entry_name) {
                return Some(EntryType::File);
            }

        None
    }

    /// List all entries in a directory by path.
    ///
    /// Returns a unified list of files, directories, and symlinks as `DirEntry` enum variants.
    /// This is the async equivalent of `VaultOperations::list_by_path()`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory within the vault (e.g., "" for root, "documents" for a subdirectory)
    ///
    /// # Errors
    ///
    /// Returns an error if the path doesn't exist or isn't a directory.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub async fn list_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<Vec<DirEntry>, VaultOperationError> {
        let vault_path = VaultPath::new(path.as_ref());

        let dir_id = if vault_path.is_root() {
            DirId::root()
        } else {
            let (resolved_id, is_dir) = self.resolve_path(vault_path.as_str()).await?;
            if !is_dir {
                return Err(VaultOperationError::NotADirectory {
                    path: vault_path.to_string(),
                });
            }
            resolved_id
        };

        self.list(&dir_id).await
    }

    /// Get entry information by path.
    ///
    /// Returns a `DirEntry` with full metadata for the entry at the given path.
    /// This is more informative than `entry_type()` as it includes the full info struct.
    ///
    /// # Arguments
    ///
    /// * `path` - Path within the vault (e.g., "documents/file.txt")
    ///
    /// # Returns
    ///
    /// - `Some(DirEntry::File(info))` for files
    /// - `Some(DirEntry::Directory(info))` for directories
    /// - `Some(DirEntry::Symlink(info))` for symlinks
    /// - `None` if nothing exists at the path
    #[instrument(level = "trace", skip(self), fields(path = %path.as_ref()))]
    pub async fn get_entry(&self, path: impl AsRef<str>) -> Option<DirEntry> {
        let vault_path = VaultPath::new(path.as_ref());

        if vault_path.is_root() {
            return Some(DirEntry::Directory(VaultDirectoryInfo {
                name: String::new(),
                directory_id: DirId::root(),
                encrypted_path: self.core.vault_path().join("d"),
                parent_directory_id: DirId::root(),
            }));
        }

        let (parent_path, entry_name) = vault_path.split()?;

        // Resolve parent directory
        let parent_dir_id = if parent_path.is_root() {
            DirId::root()
        } else {
            match self.resolve_path(parent_path.as_str()).await {
                Ok((dir_id, true)) => dir_id,
                _ => return None,
            }
        };

        // Check symlink first
        if let Ok(symlinks) = self.list_symlinks(&parent_dir_id).await
            && let Some(symlink) = symlinks.into_iter().find(|s| s.name == entry_name) {
                return Some(DirEntry::Symlink(symlink));
            }

        // Check directory
        if let Ok(dirs) = self.list_directories(&parent_dir_id).await
            && let Some(dir) = dirs.into_iter().find(|d| d.name == entry_name) {
                return Some(DirEntry::Directory(dir));
            }

        // Check file
        if let Ok(files) = self.list_files(&parent_dir_id).await
            && let Some(file) = files.into_iter().find(|f| f.name == entry_name) {
                return Some(DirEntry::File(file));
            }

        None
    }

    /// Rename a directory by its path.
    ///
    /// Convenience wrapper that accepts a path string instead of a DirId.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory to rename (e.g., "projects/old_name")
    /// * `new_name` - New name for the directory
    ///
    /// # Errors
    ///
    /// Returns an error if the directory doesn't exist or the rename fails.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref(), new_name = new_name))]
    pub async fn rename_directory_by_path(
        &self,
        path: impl AsRef<str>,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        let (parent_dir_id, old_name) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(parent_dir_id = %parent_dir_id, old_name = %old_name, "Resolved path for directory rename");
        self.rename_directory(&parent_dir_id, &old_name, new_name).await
    }

    /// Read a symlink target by its path.
    ///
    /// Convenience wrapper that accepts a path string instead of a DirId.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the symlink (e.g., "links/my_symlink")
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink doesn't exist.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub async fn read_symlink_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<String, VaultOperationError> {
        let (dir_id, name) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(dir_id = %dir_id, name = %name, "Resolved path for symlink read");
        self.read_symlink(&dir_id, &name).await
    }

    /// Create a symlink by its path.
    ///
    /// Convenience wrapper that accepts a path string instead of a DirId.
    ///
    /// # Arguments
    ///
    /// * `path` - Path for the new symlink (e.g., "links/my_symlink")
    /// * `target` - Target path the symlink should point to
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory doesn't exist or a symlink already exists.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref(), target = target))]
    pub async fn create_symlink_by_path(
        &self,
        path: impl AsRef<str>,
        target: &str,
    ) -> Result<(), VaultWriteError> {
        let (dir_id, name) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(dir_id = %dir_id, name = %name, "Resolved path for symlink creation");
        self.create_symlink(&dir_id, &name, target).await
    }

    /// Delete a symlink by its path.
    ///
    /// Convenience wrapper that accepts a path string instead of a DirId.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the symlink to delete (e.g., "links/my_symlink")
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink doesn't exist.
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub async fn delete_symlink_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<(), VaultWriteError> {
        let (dir_id, name) = self.resolve_parent_path(path.as_ref()).await?;
        debug!(dir_id = %dir_id, name = %name, "Resolved path for symlink deletion");
        self.delete_symlink(&dir_id, &name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_async_vault_error_display() {
        let err = AsyncVaultError::VaultOperation(Box::new(VaultOperationError::EmptyPath));
        assert!(err.to_string().contains("Empty path"));
    }

    // Compile-time assertions for Send/Sync bounds
    const _: () = {
        const fn assert_send<T: Send>() {}
        // VaultOperationsAsync is Send (can be moved to another thread)
        assert_send::<VaultOperationsAsync>();
    };
}
