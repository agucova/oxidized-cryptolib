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

use futures::stream::{self, StreamExt};

use crate::{
    crypto::keys::MasterKey,
    fs::file::DecryptedFile,
    fs::file_async::decrypt_file_with_context_async,
    fs::name::{create_c9s_filename, decrypt_filename, encrypt_filename},
    fs::streaming::{VaultFileReader, VaultFileWriter},
    fs::symlink::{decrypt_symlink_target, encrypt_symlink_target},
    vault::cache::VaultCache,
    vault::config::{
        extract_master_key, validate_vault_claims, CipherCombo, ClaimValidationError, VaultError,
    },
    vault::handles::VaultHandleTable,
    vault::locks::{VaultLockManager, VaultLockRegistry},
    vault::ops::{
        calculate_directory_lookup_paths, calculate_file_lookup_paths,
        calculate_symlink_lookup_paths, is_regular_entry, is_shortened_entry, VaultCore,
    },
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
///
pub struct VaultOperationsAsync {
    /// Core vault state and pure operations (shared with sync implementation).
    core: VaultCore,
    /// The master key wrapped in Arc for async sharing.
    master_key: Arc<MasterKey>,
    /// Lock manager for concurrent access (shared across instances).
    lock_manager: Arc<VaultLockManager>,
    /// Handle table for tracking open files (shared across instances).
    handle_table: Arc<VaultHandleTable>,
    /// Shared cache for expensive operations (encrypted filenames, etc.).
    cache: Arc<VaultCache>,
    /// Lock contention metrics for profiling (shared across instances).
    lock_metrics: Arc<crate::vault::lock_metrics::LockMetrics>,
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

        let cipher_combo = claims.cipher_combo().ok_or_else(|| {
            VaultError::ClaimValidation(ClaimValidationError::UnsupportedCipherCombo(
                claims.cipher_combo_str().to_string(),
            ))
        })?;
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

    /// Open an existing vault using a pre-validated password.
    ///
    /// This is the second phase of the two-phase unlock flow. Use this method
    /// after successfully calling [`PasswordValidator::validate()`] to create
    /// vault operations without re-validating the password.
    ///
    /// This approach provides:
    /// - Fast feedback on wrong passwords (validation phase)
    /// - Timeout protection against stale mounts (validation phase)
    /// - Clean separation between password validation and mount operations
    ///
    /// # Arguments
    ///
    /// * `validated` - A validated password from `PasswordValidator::validate()`
    ///
    /// # Example
    ///
    /// ```ignore
    /// use oxcrypt_core::vault::{PasswordValidator, VaultOperationsAsync};
    /// use std::time::Duration;
    ///
    /// // Phase 1: Validate password (can timeout, fast error on wrong password)
    /// let validator = PasswordValidator::new(&vault_path);
    /// let validated = validator.validate("password", Duration::from_secs(5))?;
    ///
    /// // Phase 2: Create operations (uses already-validated key, no re-validation)
    /// let ops = VaultOperationsAsync::from_validated(validated);
    /// ```
    #[instrument(level = "info", skip(validated), fields(vault_path = %validated.vault_path().display()))]
    pub fn from_validated(validated: &super::password::ValidatedPassword) -> Self {
        info!(
            cipher_combo = ?validated.cipher_combo(),
            shortening_threshold = validated.shortening_threshold(),
            "Creating VaultOperationsAsync from validated password"
        );

        Self::with_options_arc(
            validated.vault_path(),
            validated.master_key(),
            validated.shortening_threshold(),
            validated.cipher_combo(),
        )
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
            cache: Arc::new(VaultCache::new()),
            lock_metrics: Arc::new(crate::vault::lock_metrics::LockMetrics::new()),
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
            cache: Arc::new(VaultCache::new()),
            lock_metrics: Arc::new(crate::vault::lock_metrics::LockMetrics::new()),
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

    /// Returns a reference to the shared cache.
    pub fn cache(&self) -> &Arc<VaultCache> {
        &self.cache
    }

    /// Returns a reference to the lock metrics for profiling.
    pub fn lock_metrics(&self) -> &Arc<crate::vault::lock_metrics::LockMetrics> {
        &self.lock_metrics
    }

    /// Create a sync operations handle sharing the same vault state.
    ///
    /// This method creates a `VaultOperations` instance that shares the same
    /// vault configuration and master key as this async instance. Useful for
    /// implementing sync fast paths that avoid async task spawning overhead.
    ///
    /// The master key is cloned (one-time cost), but the vault configuration
    /// is shared.
    ///
    /// # Errors
    ///
    /// Returns an error if the master key cannot be cloned due to memory
    /// protection issues.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let async_ops = VaultOperationsAsync::open(&vault_path, "password")?;
    /// let sync_ops = async_ops.as_sync()?;
    ///
    /// // Both can perform the same operations, sync_ops uses std::fs
    /// let async_result = async_ops.find_file(&root, "test.txt").await?;
    /// let sync_result = sync_ops.find_file(&root, "test.txt")?;
    /// ```
    pub fn as_sync(&self) -> Result<VaultOperations, crate::crypto::keys::KeyAccessError> {
        let key_clone = self.master_key.as_ref().try_clone()?;
        Ok(VaultOperations::with_cache(
            self.vault_path(),
            key_clone,
            self.shortening_threshold(),
            self.cipher_combo(),
            Arc::clone(&self.cache),
        ))
    }

    /// Try to acquire a non-blocking directory read lock.
    ///
    /// This method attempts to acquire a read lock on a directory without
    /// blocking. Returns `Some(guard)` if the lock is available immediately,
    /// or `None` if it's currently held by a writer.
    ///
    /// Useful for implementing optimistic sync fast paths that fall back to
    /// async when locks are contended.
    ///
    /// # Arguments
    ///
    /// * `dir_id` - The directory ID to lock
    ///
    /// # Returns
    ///
    /// * `Some(guard)` - Lock acquired successfully (non-blocking)
    /// * `None` - Lock is contended, should fall back to async path
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(_guard) = ops.try_directory_read_sync(&dir_id) {
    ///     // Fast path: lock acquired, use sync operations
    ///     let sync_ops = ops.as_sync()?;
    ///     sync_ops.find_file(&dir_id, "file.txt")?
    /// } else {
    ///     // Slow path: lock contended, use async operations
    ///     ops.find_file(&dir_id, "file.txt").await?
    /// }
    /// ```
    pub fn try_directory_read_sync(&self, dir_id: &DirId)
        -> Option<tokio::sync::OwnedRwLockReadGuard<()>>
    {
        let lock = self.lock_manager.directory_lock(dir_id);
        lock.try_read_owned().ok()
    }

    /// Encrypt a filename with caching.
    ///
    /// AES-SIV encryption is deterministic, so (dir_id, name) always produces
    /// the same encrypted result. This method caches results to avoid repeated
    /// expensive AES-SIV operations.
    #[inline]
    fn encrypt_filename_cached(
        &self,
        name: &str,
        dir_id: &str,
    ) -> Result<String, VaultOperationError> {
        // Check cache first
        if let Some(cached) = self.cache.get_encrypted_name(dir_id, name) {
            trace!(name = %name, dir_id = %dir_id, "encrypted filename cache hit");
            return Ok(cached);
        }

        // Cache miss - encrypt and store
        let encrypted = encrypt_filename(name, dir_id, &self.master_key)?;
        self.cache.insert_encrypted_name(dir_id, name, encrypted.clone());
        trace!(name = %name, dir_id = %dir_id, "encrypted filename cache miss");
        Ok(encrypted)
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
        // Try sync fast path first
        if let Some(_guard) = self.try_directory_read_sync(directory_id) {
            trace!("Using sync fast path for list_files");
            let sync_ops = self.as_sync().map_err(|e| VaultOperationError::KeyAccess { source: e })?;
            return Ok(sync_ops.list_files(directory_id)?);
        }

        // Fall back to async path
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Using async path for list_files");
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
        // Pre-allocate with typical directory size to avoid reallocations.
        // Most directories have fewer than 64 entries; shortened names are rare.
        let mut regular_files: Vec<(PathBuf, String, u64)> = Vec::with_capacity(64); // (path, encrypted_name, size)
        let mut shortened_paths: Vec<PathBuf> = Vec::with_capacity(4);
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
            if file_type.is_dir() && is_regular_entry(&file_name) {
                continue;
            }

            // Skip other directories that aren't .c9s
            if file_type.is_dir() && !is_shortened_entry(&file_name) {
                continue;
            }

            if is_regular_entry(&file_name) {
                let metadata = fs::metadata(&path).await?;
                regular_files.push((path, file_name, metadata.len()));
            } else if is_shortened_entry(&file_name) && file_type.is_dir() {
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

        // Phase 3: Handle shortened files in parallel (these have their own async I/O for reading name.c9s)
        // Using buffer_unordered for concurrent processing - critical for high-latency backends
        let shortened_files: Vec<VaultFileInfo> = stream::iter(shortened_paths)
            .map(|path| async move { self.read_shortened_file_info(&path, directory_id).await })
            .buffer_unordered(32) // Process up to 32 shortened files concurrently
            .filter_map(|result| async move { result.ok() })
            .collect()
            .await;

        let mut files = decrypted_regular;
        files.extend(shortened_files);

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
        // Try sync fast path first
        if let Some(_guard) = self.try_directory_read_sync(directory_id) {
            trace!("Using sync fast path for list_directories");
            let sync_ops = self.as_sync().map_err(|e| VaultOperationError::KeyAccess { source: e })?;
            return Ok(sync_ops.list_directories(directory_id)?);
        }

        // Fall back to async path
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Using async path for list_directories");
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
        // Pre-allocate with typical directory size to avoid reallocations.
        // Regular directories: (path, encrypted_name, dir_id_content)
        let mut regular_dirs: Vec<(PathBuf, String, String)> = Vec::with_capacity(32);
        let mut shortened_paths: Vec<PathBuf> = Vec::with_capacity(4);
        let mut entries = fs::read_dir(&dir_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            let file_type = entry.file_type().await?;

            if file_type.is_dir() && is_regular_entry(&file_name) {
                // This is a regular directory - read dir.c9r content
                trace!(encrypted_name = %file_name, "Processing directory entry");
                let dir_id_file = path.join("dir.c9r");
                if let Ok(dir_id_content) = fs::read_to_string(&dir_id_file).await {
                    regular_dirs.push((path, file_name, dir_id_content));
                }
            } else if file_type.is_dir() && is_shortened_entry(&file_name) {
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

        // Phase 3: Handle shortened directories in parallel (these have their own async I/O for reading name.c9s)
        // Using buffer_unordered for concurrent processing - critical for high-latency backends
        let shortened_dirs: Vec<VaultDirectoryInfo> = stream::iter(shortened_paths)
            .map(|path| async move {
                self.read_shortened_directory_info(&path, directory_id).await
            })
            .buffer_unordered(32) // Process up to 32 shortened directories concurrently
            .filter_map(|result| async move { result.ok() })
            .collect()
            .await;

        let mut directories = decrypted_regular;
        directories.extend(shortened_dirs);

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
        // Try sync fast path first
        if let Some(_guard) = self.try_directory_read_sync(directory_id) {
            trace!("Using sync fast path for find_file");
            let sync_ops = self.as_sync().map_err(|e| VaultOperationError::KeyAccess { source: e })?;
            return Ok(sync_ops.find_file(directory_id, filename)?);
        }

        // Fall back to async path
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Using async path for find_file");
        self.find_file_unlocked(directory_id, filename).await
    }

    /// Internal implementation of find_file without locking.
    async fn find_file_unlocked(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<Option<VaultFileInfo>, VaultOperationError> {
        let storage_path = self.calculate_directory_storage_path(directory_id)?;

        // Encrypt the filename to get the expected path (cached)
        let encrypted_name = self.encrypt_filename_cached(filename, directory_id.as_str())?;

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
        // Try sync fast path first
        if let Some(_guard) = self.try_directory_read_sync(parent_directory_id) {
            trace!("Using sync fast path for find_directory");
            let sync_ops = self.as_sync().map_err(|e| VaultOperationError::KeyAccess { source: e })?;
            return Ok(sync_ops.find_directory(parent_directory_id, dir_name)?);
        }

        // Fall back to async path
        let _guard = self.lock_manager.directory_read(parent_directory_id).await;
        trace!("Using async path for find_directory");
        self.find_directory_unlocked(parent_directory_id, dir_name).await
    }

    /// Internal implementation of find_directory without locking.
    async fn find_directory_unlocked(
        &self,
        parent_directory_id: &DirId,
        dir_name: &str,
    ) -> Result<Option<VaultDirectoryInfo>, VaultOperationError> {
        let storage_path = self.calculate_directory_storage_path(parent_directory_id)?;

        // Encrypt the directory name to get the expected path (cached)
        let encrypted_name = self.encrypt_filename_cached(dir_name, parent_directory_id.as_str())?;

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

    /// Find a symlink by name in a directory using O(1) path lookup.
    ///
    /// Instead of listing all symlinks and searching linearly, this method
    /// calculates the expected encrypted path directly and checks if it exists.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The parent directory's ID
    /// * `symlink_name` - The decrypted name of the symlink to find
    ///
    /// # Returns
    ///
    /// `Some(VaultSymlinkInfo)` if found, `None` if not found.
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), symlink_name = %symlink_name))]
    pub async fn find_symlink(
        &self,
        directory_id: &DirId,
        symlink_name: &str,
    ) -> Result<Option<VaultSymlinkInfo>, VaultOperationError> {
        // Try sync fast path first
        if let Some(_guard) = self.try_directory_read_sync(directory_id) {
            trace!("Using sync fast path for find_symlink");
            let sync_ops = self.as_sync().map_err(|e| VaultOperationError::KeyAccess { source: e })?;
            return Ok(sync_ops.find_symlink(directory_id, symlink_name)?);
        }

        // Fall back to async path
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Using async path for find_symlink");
        self.find_symlink_unlocked(directory_id, symlink_name).await
    }

    /// Internal implementation of find_symlink without locking.
    async fn find_symlink_unlocked(
        &self,
        directory_id: &DirId,
        symlink_name: &str,
    ) -> Result<Option<VaultSymlinkInfo>, VaultOperationError> {
        let storage_path = self.calculate_directory_storage_path(directory_id)?;

        // Encrypt the symlink name to get the expected path (cached)
        let encrypted_name = self.encrypt_filename_cached(symlink_name, directory_id.as_str())?;

        // Calculate paths using shared helper
        let paths = calculate_symlink_lookup_paths(
            &storage_path,
            &encrypted_name,
            self.core.shortening_threshold(),
        );

        // Perform async I/O to check if symlink exists and read its target
        match fs::read(&paths.content_path).await {
            Ok(encrypted_data) => {
                let target = decrypt_symlink_target(&encrypted_data, &self.master_key)?;
                trace!(target_len = target.len(), shortened = paths.is_shortened, "Found symlink");
                Ok(Some(VaultSymlinkInfo {
                    name: symlink_name.to_string(),
                    target,
                    encrypted_path: paths.entry_path,
                    is_shortened: paths.is_shortened,
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                trace!(shortened = paths.is_shortened, "Symlink not found");
                Ok(None)
            }
            Err(e) => Err(VaultOperationError::Io {
                source: e,
                context: VaultOpContext::new()
                    .with_filename(symlink_name)
                    .with_dir_id(directory_id.as_str())
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
                context: Box::new(VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str())
                    .with_encrypted_path(&file_info.encrypted_path)),
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

    /// Open a file for streaming reads without holding vault locks.
    ///
    /// Unlike [`open_file()`], this method does NOT transfer locks to the reader.
    /// Locks are only held during the initial file lookup, then released.
    ///
    /// This is the preferred method for FUSE where files may remain open for
    /// extended periods. The underlying OS file handle keeps the file accessible
    /// even if it's unlinked at the vault level (POSIX semantics).
    ///
    /// # Safety
    ///
    /// This relies on OS file handle semantics - once the file is opened,
    /// reads will succeed even if the file is deleted. However, there's no
    /// protection against concurrent vault-level modifications to the same file.
    /// This is acceptable because:
    /// - FUSE writes use a separate WriteBuffer path that flushes on release
    /// - No concurrent writes to the same open file handle are possible
    ///
    /// # Example
    ///
    /// ```ignore
    /// let reader = ops.open_file_unlocked(&dir_id, "data.txt").await?;
    /// // No vault locks held - directory operations won't block
    /// let data = reader.read_range(0, 1024).await?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), filename = %filename))]
    pub async fn open_file_unlocked(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<VaultFileReader, VaultOperationError> {
        debug!("Opening file for streaming read (unlocked)");

        // Acquire locks ONLY for the duration of file lookup
        // These will be dropped when this function returns
        let _dir_guard = self.lock_manager.directory_read(directory_id).await;
        let _file_guard = self.lock_manager.file_read(directory_id, filename).await;
        trace!("Acquired temporary locks for file lookup");

        // Find the encrypted file path
        let file_info = self.find_file_unlocked(directory_id, filename).await?.ok_or_else(|| {
            warn!("File not found in directory");
            VaultOperationError::FileNotFound {
                filename: filename.to_string(),
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str()),
            }
        })?;

        debug!(encrypted_path = %file_info.encrypted_path.display(), cipher_combo = ?self.core.cipher_combo(), "Found file, opening for streaming (unlocked)");

        // Open the file - this opens the underlying OS file handle
        let reader = VaultFileReader::open_with_cipher(
            &file_info.encrypted_path,
            &self.master_key,
            self.core.cipher_combo(),
        )
            .await
            .map_err(|e| VaultOperationError::Streaming {
                source: Box::new(e),
                context: Box::new(VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(directory_id.as_str())
                    .with_encrypted_path(&file_info.encrypted_path)),
            })?;

        // NOTE: We intentionally DO NOT call reader.with_locks() here.
        // The locks (_dir_guard, _file_guard) will be dropped when this function returns.
        // The reader keeps the OS file handle open, which is sufficient for reads.

        info!(
            filename = %filename,
            plaintext_size = reader.plaintext_size(),
            "File opened for streaming without locks"
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
            context: Box::new(VaultOpContext::new().with_encrypted_path(&storage_path)),
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
                context: Box::new(VaultOpContext::new().with_encrypted_path(&short_dir)),
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
                    .with_encrypted_path(&dest_path)
                    .into_box(),
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
            context: Box::new(VaultOpContext::new().with_encrypted_path(&storage_path)),
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
            context: Box::new(VaultOpContext::new().with_encrypted_path(&short_dir)),
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
                context: Box::new(VaultOpContext::new().with_encrypted_path(path)),
            })?;

            let temp_path = parent.join(format!(".tmp.{}", uuid::Uuid::new_v4()));

            // Write to temp file
            fs::write(&temp_path, data).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&temp_path)),
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
                    context: Box::new(VaultOpContext::new().with_encrypted_path(path)),
                });
            }
        } else {
            // New file: direct write (no existing data at risk)
            fs::write(path, data).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(path)),
            })?;
        }

        Ok(())
    }

    /// Sync an encrypted file to disk.
    ///
    /// This ensures data written via `write_file()` or `safe_write()` is actually
    /// persisted to stable storage, not just in the OS page cache.
    ///
    /// # Arguments
    /// * `encrypted_path` - Path to the encrypted file to sync
    /// * `datasync` - If true, only sync data (fdatasync semantics). If false,
    ///   sync data and metadata (fsync semantics).
    ///
    /// # POSIX Semantics
    /// - `fsync` (datasync=false): Syncs file data and all metadata (size, timestamps, etc.)
    /// - `fdatasync` (datasync=true): Syncs file data and only metadata needed for retrieval
    ///   (e.g., file size, but not access time)
    pub async fn sync_encrypted_file(
        &self,
        encrypted_path: &Path,
        datasync: bool,
    ) -> Result<(), VaultWriteError> {
        let file = fs::File::open(encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(encrypted_path)),
        })?;

        if datasync {
            file.sync_data().await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(encrypted_path)),
            })?;
        } else {
            file.sync_all().await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(encrypted_path)),
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
            context: Box::new(VaultOpContext::new().with_encrypted_path(&parent_storage_path)),
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
                context: Box::new(VaultOpContext::new().with_encrypted_path(&encrypted_dir_path)),
            })?;
            self.safe_write(&encrypted_dir_path.join("dir.c9r"), dir_id.as_str().as_bytes()).await?;
        }

        // Create the storage directory for this new directory
        let new_storage_path = self.calculate_directory_storage_path(&dir_id)?;
        fs::create_dir_all(&new_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&new_storage_path)),
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
            context: Box::new(VaultOpContext::new().with_encrypted_path(&short_dir)),
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
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: Box::new(ctx.clone()),
            },
        })?.ok_or_else(|| VaultWriteError::FileNotFound {
            filename: filename.to_string(),
            context: Box::new(ctx.clone()),
        })?;

        debug!(is_shortened = file_info.is_shortened, encrypted_path = %file_info.encrypted_path.display(), "Removing encrypted file");

        if file_info.is_shortened {
            // Remove the entire .c9s directory
            let parent = file_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: Box::new(ctx.clone().with_encrypted_path(&file_info.encrypted_path)),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(parent)),
            })?;
        } else {
            fs::remove_file(&file_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&file_info.encrypted_path)),
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
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: Box::new(ctx.clone()),
            },
        })?.ok_or_else(|| VaultWriteError::DirectoryNotFound {
            name: dir_name.to_string(),
            context: Box::new(ctx.clone()),
        })?;

        trace!(target_dir_id = %dir_info.directory_id.as_str(), "Found directory to delete");

        // Acquire target directory write lock (in addition to parent lock)
        let _target_guard = self.lock_manager.directory_write(&dir_info.directory_id).await;
        trace!("Acquired target directory write lock for delete_directory");

        // Check directory is empty (use unlocked versions since we hold both locks)
        let target_ctx = ctx.clone().with_dir_id(dir_info.directory_id.as_str());
        let files = self.list_files_unlocked(&dir_info.directory_id).await.map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: Box::new(target_ctx.clone()),
            },
        })?;
        let subdirs = self.list_directories_unlocked(&dir_info.directory_id).await.map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
            other => VaultWriteError::Io {
                source: std::io::Error::other(other.to_string()),
                context: Box::new(target_ctx.clone()),
            },
        })?;

        if !files.is_empty() || !subdirs.is_empty() {
            debug!(file_count = files.len(), subdir_count = subdirs.len(), "Cannot delete non-empty directory");
            return Err(VaultWriteError::DirectoryNotEmpty {
                context: Box::new(target_ctx.with_encrypted_path(&dir_info.encrypted_path)),
            });
        }

        // Remove the storage directory
        let storage_path = self.calculate_directory_storage_path(&dir_info.directory_id)?;
        if fs::metadata(&storage_path).await.is_ok() {
            fs::remove_dir_all(&storage_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&storage_path)),
            })?;
        }

        // Remove the directory entry from parent
        if fs::metadata(&dir_info.encrypted_path).await.is_ok() {
            fs::remove_dir_all(&dir_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&dir_info.encrypted_path)),
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
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(ctx) });
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
                context: Box::new(ctx.clone()),
            }
        })?;

        // Check target doesn't exist using optimized lookup
        if self.find_file_unlocked(dir_id, new_name).await?.is_some() {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: new_name.to_string(),
                context: Box::new(ctx.clone().with_filename(new_name)),
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
                context: Box::new(ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
            })?;
            self.write_shortened_file(&storage_path, &new_encrypted_name, &file_data).await?;
        } else {
            let new_path = storage_path.join(format!("{new_encrypted_name}.c9r"));
            // Use fs::copy for efficient file copying (no memory allocation for large files)
            fs::copy(&source_info.encrypted_path, &new_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(ctx.clone().with_encrypted_path(&new_path)),
            })?;
        }

        // Remove the old file
        if source_info.is_shortened {
            let parent = source_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: Box::new(ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(parent)),
            })?;
        } else {
            fs::remove_file(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path)),
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
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(ctx) });
        }

        // Acquire parent directory write lock
        let _parent_guard = self.lock_manager.directory_write(parent_dir_id).await;
        trace!("Acquired parent directory write lock for rename_directory");

        // Find the source directory using optimized lookup
        let source_info = self
            .find_directory_unlocked(parent_dir_id, old_name)
            .await
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                other => VaultWriteError::Io {
                    source: std::io::Error::other(other.to_string()),
                    context: Box::new(ctx.clone()),
                },
            })?
            .ok_or_else(|| VaultWriteError::DirectoryNotFound {
                name: old_name.to_string(),
                context: Box::new(ctx.clone()),
            })?;

        // Check that target doesn't exist using optimized lookup
        if self
            .find_directory_unlocked(parent_dir_id, new_name)
            .await?
            .is_some()
        {
            return Err(VaultWriteError::DirectoryAlreadyExists {
                name: new_name.to_string(),
                context: Box::new(ctx.clone().with_filename(new_name)),
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
                context: Box::new(VaultOpContext::new().with_encrypted_path(&new_path)),
            })?;
            self.safe_write(&new_path.join("dir.c9r"), dir_id.as_str().as_bytes())
                .await?;
        }

        // Remove the old directory entry (not the storage directory - that stays!)
        fs::remove_dir_all(&source_info.encrypted_path)
            .await
            .map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path)),
            })?;

        info!("Directory renamed successfully");
        Ok(())
    }

    /// Move and rename a directory across parents.
    ///
    /// This preserves the directory ID and only updates the directory entry
    /// in the source and destination parent directories.
    ///
    /// # Arguments
    ///
    /// * `src_parent_dir_id` - Source parent directory ID
    /// * `src_name` - Source directory name
    /// * `dest_parent_dir_id` - Destination parent directory ID
    /// * `dest_name` - Destination directory name
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source directory doesn't exist
    /// - A directory with the destination name already exists
    /// - Source and destination are identical
    #[instrument(level = "info", skip(self), fields(src_parent_dir_id = %src_parent_dir_id.as_str(), src_name = %src_name, dest_parent_dir_id = %dest_parent_dir_id.as_str(), dest_name = %dest_name))]
    pub async fn move_and_rename_directory(
        &self,
        src_parent_dir_id: &DirId,
        src_name: &str,
        dest_parent_dir_id: &DirId,
        dest_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Moving and renaming directory in vault");

        let src_ctx = VaultOpContext::new()
            .with_filename(src_name)
            .with_dir_id(src_parent_dir_id.as_str());

        // Same directory and same name is a no-op
        if src_parent_dir_id == dest_parent_dir_id && src_name == dest_name {
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(src_ctx) });
        }

        if src_parent_dir_id == dest_parent_dir_id {
            return self.rename_directory(src_parent_dir_id, src_name, dest_name).await;
        }

        // Acquire parent directory write locks in consistent order to prevent deadlocks
        let _dir_guards = self
            .lock_manager
            .lock_directories_write_ordered(&[src_parent_dir_id, dest_parent_dir_id])
            .await;
        trace!("Acquired parent directory write locks for move_and_rename_directory");

        let source_info = self
            .find_directory_unlocked(src_parent_dir_id, src_name)
            .await
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                other => VaultWriteError::Io {
                    source: std::io::Error::other(other.to_string()),
                    context: Box::new(src_ctx.clone()),
                },
            })?
            .ok_or_else(|| VaultWriteError::DirectoryNotFound {
                name: src_name.to_string(),
                context: Box::new(src_ctx.clone()),
            })?;

        if self
            .find_directory_unlocked(dest_parent_dir_id, dest_name)
            .await?
            .is_some()
        {
            return Err(VaultWriteError::DirectoryAlreadyExists {
                name: dest_name.to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(dest_name)
                    .with_dir_id(dest_parent_dir_id.as_str())),
            });
        }

        let dest_storage_path = self.calculate_directory_storage_path(dest_parent_dir_id)?;
        fs::create_dir_all(&dest_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&dest_storage_path)),
        })?;

        let new_encrypted_name = encrypt_filename(dest_name, dest_parent_dir_id.as_str(), &self.master_key)?;
        let new_is_long = new_encrypted_name.len() > self.core.shortening_threshold();
        let dir_id = &source_info.directory_id;

        if new_is_long {
            self.create_shortened_directory(&dest_storage_path, &new_encrypted_name, dir_id)
                .await?;
        } else {
            let new_path = dest_storage_path.join(format!("{new_encrypted_name}.c9r"));
            fs::create_dir_all(&new_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&new_path)),
            })?;
            self.safe_write(&new_path.join("dir.c9r"), dir_id.as_str().as_bytes())
                .await?;
        }

        // Remove the old directory entry (not the storage directory - that stays!)
        fs::remove_dir_all(&source_info.encrypted_path)
            .await
            .map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path)),
            })?;

        info!("Directory moved successfully");
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
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(src_ctx) });
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
                context: Box::new(src_ctx.clone()),
            }
        })?;

        // Check that target doesn't exist using optimized lookup
        if self.find_file_unlocked(dest_dir_id, filename).await?.is_some() {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: filename.to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(dest_dir_id.as_str())),
            });
        }

        // Ensure destination directory exists
        let dest_storage_path = self.calculate_directory_storage_path(dest_dir_id)?;
        fs::create_dir_all(&dest_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&dest_storage_path)),
        })?;

        // Read raw encrypted file data
        let file_data = fs::read(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(src_ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
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
                context: Box::new(src_ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(parent)),
            })?;
        } else {
            fs::remove_file(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path)),
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
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(src_ctx) });
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
                context: Box::new(src_ctx.clone()),
            }
        })?;

        // Check that target doesn't exist
        if self.find_file_unlocked(dest_dir_id, dest_name).await?.is_some() {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: dest_name.to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(dest_name)
                    .with_dir_id(dest_dir_id.as_str())),
            });
        }

        // Ensure destination directory exists
        let dest_storage_path = self.calculate_directory_storage_path(dest_dir_id)?;
        fs::create_dir_all(&dest_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&dest_storage_path)),
        })?;

        // Read raw encrypted file data
        let file_data = fs::read(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(src_ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
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
                context: Box::new(src_ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(parent)),
            })?;
        } else {
            fs::remove_file(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path)),
            })?;
        }

        info!("File moved and renamed successfully");
        Ok(())
    }

    // ==================== Atomic Swap Operations (RENAME_EXCHANGE) ====================

    /// Atomically swap two files (implements RENAME_EXCHANGE semantics).
    ///
    /// After completion, path_a contains what was at path_b, and vice versa.
    /// This is required for git operations that need atomic index updates.
    ///
    /// # Algorithm
    ///
    /// Uses a 3-phase commit pattern:
    /// 1. Move A to temp location
    /// 2. Move B to A's original location
    /// 3. Move temp to B's original location
    ///
    /// If any step fails, the operation attempts to rollback.
    ///
    /// # Arguments
    ///
    /// * `dir_id_a` - Directory ID containing file A
    /// * `name_a` - Filename of file A
    /// * `dir_id_b` - Directory ID containing file B
    /// * `name_b` - Filename of file B
    ///
    /// # Cross-directory swap
    ///
    /// When files are in different directories, both filenames are re-encrypted
    /// with the new directory's ID as associated data (AES-SIV). File contents
    /// do not need re-encryption (they use the file header nonce, not directory ID).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either file doesn't exist
    /// - A file with the temp name already exists (extremely unlikely with UUID)
    /// - IO error during any phase
    #[instrument(level = "info", skip(self), fields(dir_a = %dir_id_a.as_str(), name_a = %name_a, dir_b = %dir_id_b.as_str(), name_b = %name_b))]
    pub async fn atomic_swap_files(
        &self,
        dir_id_a: &DirId,
        name_a: &str,
        dir_id_b: &DirId,
        name_b: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Atomically swapping two files");

        let ctx = VaultOpContext::new()
            .with_filename(name_a)
            .with_dir_id(dir_id_a.as_str());

        // Same file is a no-op
        if dir_id_a == dir_id_b && name_a == name_b {
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(ctx) });
        }

        // Acquire directory write locks in consistent order to prevent deadlocks
        let _dir_guards = self
            .lock_manager
            .lock_directories_write_ordered(&[dir_id_a, dir_id_b])
            .await;

        // Lock all files involved
        let _file_guard_a = self.lock_manager.file_write(dir_id_a, name_a).await;
        let _file_guard_b = self.lock_manager.file_write(dir_id_b, name_b).await;
        trace!("Acquired all locks for atomic_swap_files");

        // Verify both files exist
        let file_a_info = self.find_file_unlocked(dir_id_a, name_a).await?.ok_or_else(|| {
            VaultWriteError::FileNotFound {
                filename: name_a.to_string(),
                context: Box::new(ctx.clone()),
            }
        })?;

        let file_b_info = self.find_file_unlocked(dir_id_b, name_b).await?.ok_or_else(|| {
            VaultWriteError::FileNotFound {
                filename: name_b.to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(name_b)
                    .with_dir_id(dir_id_b.as_str())),
            }
        })?;

        // Generate a unique temp name using UUID to avoid collisions
        let temp_name = format!(".swap_temp_{}", uuid::Uuid::new_v4());

        // Get storage paths
        let storage_path_a = self.calculate_directory_storage_path(dir_id_a)?;
        let storage_path_b = self.calculate_directory_storage_path(dir_id_b)?;

        // Read raw encrypted file data for both files
        let data_a = fs::read(&file_a_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(ctx.clone().with_encrypted_path(&file_a_info.encrypted_path)),
        })?;

        let data_b = fs::read(&file_b_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new()
                .with_filename(name_b)
                .with_dir_id(dir_id_b.as_str())
                .with_encrypted_path(&file_b_info.encrypted_path)),
        })?;

        // Phase 1: Write A's data to temp location (in A's directory)
        let temp_encrypted_name = encrypt_filename(&temp_name, dir_id_a.as_str(), &self.master_key)?;
        let temp_is_long = temp_encrypted_name.len() > self.core.shortening_threshold();
        let temp_path = if temp_is_long {
            self.write_shortened_file(&storage_path_a, &temp_encrypted_name, &data_a).await?;
            // For shortened files, the path is the .c9s directory
            let hash = create_c9s_filename(&temp_encrypted_name);
            storage_path_a.join(format!("{hash}.c9s"))
        } else {
            let path = storage_path_a.join(format!("{temp_encrypted_name}.c9r"));
            self.safe_write(&path, &data_a).await?;
            path
        };

        // Phase 2: Write B's data to A's location (with A's directory ID encryption)
        // This effectively "moves" B to where A was
        let name_a_encrypted = encrypt_filename(name_a, dir_id_a.as_str(), &self.master_key)?;
        let name_a_is_long = name_a_encrypted.len() > self.core.shortening_threshold();

        let write_b_to_a_result = if name_a_is_long {
            self.write_shortened_file(&storage_path_a, &name_a_encrypted, &data_b).await.map(|_| ())
        } else {
            let new_path_a = storage_path_a.join(format!("{name_a_encrypted}.c9r"));
            self.safe_write(&new_path_a, &data_b).await
        };

        if let Err(e) = write_b_to_a_result {
            // Rollback: remove temp file
            warn!("Phase 2 failed, rolling back temp file");
            let _ = if temp_is_long {
                fs::remove_dir_all(&temp_path).await
            } else {
                fs::remove_file(&temp_path).await
            };
            return Err(e);
        }

        // Phase 3: Write temp (original A) data to B's location (with B's directory ID encryption)
        let name_b_encrypted = encrypt_filename(name_b, dir_id_b.as_str(), &self.master_key)?;
        let name_b_is_long = name_b_encrypted.len() > self.core.shortening_threshold();

        let write_a_to_b_result = if name_b_is_long {
            self.write_shortened_file(&storage_path_b, &name_b_encrypted, &data_a).await.map(|_| ())
        } else {
            let new_path_b = storage_path_b.join(format!("{name_b_encrypted}.c9r"));
            self.safe_write(&new_path_b, &data_a).await
        };

        if let Err(e) = write_a_to_b_result {
            // Rollback: restore A from temp, remove B's overwritten data
            warn!("Phase 3 failed, attempting rollback");

            // Try to restore A from temp
            if name_a_is_long {
                let _ = self.write_shortened_file(&storage_path_a, &name_a_encrypted, &data_a).await;
            } else {
                let restore_path = storage_path_a.join(format!("{name_a_encrypted}.c9r"));
                let _ = self.safe_write(&restore_path, &data_a).await;
            }

            // Remove temp
            let _ = if temp_is_long {
                fs::remove_dir_all(&temp_path).await
            } else {
                fs::remove_file(&temp_path).await
            };

            return Err(e);
        }

        // Cleanup: Remove original files and temp
        // Remove original A (now overwritten with B's data, the old encrypted name still exists)
        if file_a_info.is_shortened {
            let parent = file_a_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory for file A".to_string(),
                context: Box::new(ctx.clone().with_encrypted_path(&file_a_info.encrypted_path)),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(parent)),
            })?;
        } else {
            fs::remove_file(&file_a_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&file_a_info.encrypted_path)),
            })?;
        }

        // Remove original B
        if file_b_info.is_shortened {
            let parent = file_b_info.encrypted_path.parent().ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory for file B".to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(name_b)
                    .with_encrypted_path(&file_b_info.encrypted_path)),
            })?;
            fs::remove_dir_all(parent).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(parent)),
            })?;
        } else {
            fs::remove_file(&file_b_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&file_b_info.encrypted_path)),
            })?;
        }

        // Remove temp file
        if temp_is_long {
            fs::remove_dir_all(&temp_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&temp_path)),
            })?;
        } else {
            fs::remove_file(&temp_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&temp_path)),
            })?;
        }

        info!("Files swapped successfully");
        Ok(())
    }

    /// Atomically swap two directories within the same parent.
    ///
    /// After completion, the directory entries are swapped but the directory IDs
    /// (and thus all contents) remain unchanged.
    ///
    /// # Limitations
    ///
    /// Cross-directory swaps (directories in different parent directories) are
    /// **not supported** because they would require recursively re-encrypting all
    /// descendant filenames with new directory IDs.
    ///
    /// # Arguments
    ///
    /// * `parent_dir_id` - The parent directory containing both directories
    /// * `name_a` - Name of first directory
    /// * `name_b` - Name of second directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either directory doesn't exist
    /// - IO error during swap
    #[instrument(level = "info", skip(self), fields(parent = %parent_dir_id.as_str(), name_a = %name_a, name_b = %name_b))]
    pub async fn atomic_swap_directories(
        &self,
        parent_dir_id: &DirId,
        name_a: &str,
        name_b: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Atomically swapping two directories");

        let ctx = VaultOpContext::new()
            .with_filename(name_a)
            .with_dir_id(parent_dir_id.as_str());

        // Same directory is a no-op
        if name_a == name_b {
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(ctx) });
        }

        // Acquire parent directory write lock
        let _parent_guard = self.lock_manager.directory_write(parent_dir_id).await;
        trace!("Acquired parent directory write lock for atomic_swap_directories");

        // Find both directories
        let dir_a_info = self
            .find_directory_unlocked(parent_dir_id, name_a)
            .await
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                other => VaultWriteError::Io {
                    source: std::io::Error::other(other.to_string()),
                    context: Box::new(ctx.clone()),
                },
            })?
            .ok_or_else(|| VaultWriteError::DirectoryNotFound {
                name: name_a.to_string(),
                context: Box::new(ctx.clone()),
            })?;

        let dir_b_info = self
            .find_directory_unlocked(parent_dir_id, name_b)
            .await
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                other => VaultWriteError::Io {
                    source: std::io::Error::other(other.to_string()),
                    context: Box::new(VaultOpContext::new()
                        .with_filename(name_b)
                        .with_dir_id(parent_dir_id.as_str())),
                },
            })?
            .ok_or_else(|| VaultWriteError::DirectoryNotFound {
                name: name_b.to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(name_b)
                    .with_dir_id(parent_dir_id.as_str())),
            })?;

        let parent_storage_path = self.calculate_directory_storage_path(parent_dir_id)?;

        // For directory swap, we just need to swap the encrypted directory entries
        // The directory IDs stay the same (A's ID now lives at B's name, and vice versa)

        // Generate temp name
        let temp_name = format!(".swap_temp_{}", uuid::Uuid::new_v4());
        let temp_encrypted_name = encrypt_filename(&temp_name, parent_dir_id.as_str(), &self.master_key)?;
        let temp_is_long = temp_encrypted_name.len() > self.core.shortening_threshold();

        // Phase 1: Create temp directory entry for A's directory ID
        if temp_is_long {
            self.create_shortened_directory(&parent_storage_path, &temp_encrypted_name, &dir_a_info.directory_id)
                .await?;
        } else {
            let temp_path = parent_storage_path.join(format!("{temp_encrypted_name}.c9r"));
            fs::create_dir_all(&temp_path).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&temp_path)),
            })?;
            self.safe_write(&temp_path.join("dir.c9r"), dir_a_info.directory_id.as_str().as_bytes())
                .await?;
        }

        // Phase 2: Create new entry for B's ID at A's name
        let name_a_encrypted = encrypt_filename(name_a, parent_dir_id.as_str(), &self.master_key)?;
        let name_a_is_long = name_a_encrypted.len() > self.core.shortening_threshold();

        if name_a_is_long {
            self.create_shortened_directory(&parent_storage_path, &name_a_encrypted, &dir_b_info.directory_id)
                .await?;
        } else {
            let new_path_a = parent_storage_path.join(format!("{name_a_encrypted}.c9r"));
            fs::create_dir_all(&new_path_a).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&new_path_a)),
            })?;
            self.safe_write(&new_path_a.join("dir.c9r"), dir_b_info.directory_id.as_str().as_bytes())
                .await?;
        }

        // Phase 3: Create new entry for A's ID (from temp) at B's name
        let name_b_encrypted = encrypt_filename(name_b, parent_dir_id.as_str(), &self.master_key)?;
        let name_b_is_long = name_b_encrypted.len() > self.core.shortening_threshold();

        if name_b_is_long {
            self.create_shortened_directory(&parent_storage_path, &name_b_encrypted, &dir_a_info.directory_id)
                .await?;
        } else {
            let new_path_b = parent_storage_path.join(format!("{name_b_encrypted}.c9r"));
            fs::create_dir_all(&new_path_b).await.map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&new_path_b)),
            })?;
            self.safe_write(&new_path_b.join("dir.c9r"), dir_a_info.directory_id.as_str().as_bytes())
                .await?;
        }

        // Cleanup: Remove original directory entries and temp
        fs::remove_dir_all(&dir_a_info.encrypted_path)
            .await
            .map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&dir_a_info.encrypted_path)),
            })?;

        fs::remove_dir_all(&dir_b_info.encrypted_path)
            .await
            .map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(VaultOpContext::new().with_encrypted_path(&dir_b_info.encrypted_path)),
            })?;

        // Remove temp
        let temp_path = if temp_is_long {
            let hash = create_c9s_filename(&temp_encrypted_name);
            parent_storage_path.join(format!("{hash}.c9s"))
        } else {
            parent_storage_path.join(format!("{temp_encrypted_name}.c9r"))
        };
        fs::remove_dir_all(&temp_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&temp_path)),
        })?;

        info!("Directories swapped successfully");
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
        // Try sync fast path first
        if let Some(_guard) = self.try_directory_read_sync(directory_id) {
            trace!("Using sync fast path for list_symlinks");
            let sync_ops = self.as_sync().map_err(|e| VaultOperationError::KeyAccess { source: e })?;
            return Ok(sync_ops.list_symlinks(directory_id)?);
        }

        // Fall back to async path
        let _guard = self.lock_manager.directory_read(directory_id).await;
        trace!("Using async path for list_symlinks");
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
        // Collect files first (usually the largest collection), then reserve for total.
        let files = self.list_files(directory_id).await?;
        let dirs = self.list_directories(directory_id).await?;
        let symlinks = self.list_symlinks(directory_id).await?;

        // Pre-allocate with exact capacity now that we know the total count.
        let mut entries = Vec::with_capacity(files.len() + dirs.len() + symlinks.len());
        entries.extend(files.into_iter().map(DirEntry::File));
        entries.extend(dirs.into_iter().map(DirEntry::Directory));
        entries.extend(symlinks.into_iter().map(DirEntry::Symlink));

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

        // Phase 1: Collect all potential symlink entries (path, encrypted_name, is_shortened)
        // We only do metadata checks here, deferring the actual symlink.c9r check to parallel phase
        // Pre-allocate with modest capacity - symlinks are typically rare in vaults.
        let mut regular_symlinks: Vec<(PathBuf, String)> = Vec::with_capacity(16); // (path, encrypted_name)
        let mut shortened_symlinks: Vec<PathBuf> = Vec::with_capacity(4);

        let mut entries = fs::read_dir(&dir_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            let Ok(metadata) = fs::metadata(&path).await else { continue };

            if metadata.is_dir() && is_regular_entry(&file_name) {
                // Potential regular symlink - will verify symlink.c9r exists in parallel phase
                regular_symlinks.push((path, file_name));
            } else if metadata.is_dir() && is_shortened_entry(&file_name) {
                // Potential shortened symlink - will verify symlink.c9r exists in parallel phase
                shortened_symlinks.push(path);
            }
        }

        // Phase 2: Process regular symlinks in parallel
        // Each task checks for symlink.c9r and reads symlink info if present
        let regular_results: Vec<VaultSymlinkInfo> = stream::iter(regular_symlinks)
            .map(|(path, file_name)| async move {
                let symlink_file = path.join("symlink.c9r");
                if fs::try_exists(&symlink_file).await.unwrap_or(false) {
                    trace!(encrypted_name = %file_name, "Processing symlink entry");
                    self.read_symlink_info_async(&path, &file_name, directory_id, false)
                        .await
                        .ok()
                } else {
                    None
                }
            })
            .buffer_unordered(32) // Process up to 32 symlinks concurrently
            .filter_map(|result| async move { result })
            .collect()
            .await;

        // Phase 3: Process shortened symlinks in parallel
        let shortened_results: Vec<VaultSymlinkInfo> = stream::iter(shortened_symlinks)
            .map(|path| async move {
                let symlink_file = path.join("symlink.c9r");
                if fs::try_exists(&symlink_file).await.unwrap_or(false) {
                    trace!(path = %path.display(), "Processing shortened symlink entry");
                    self.read_shortened_symlink_info_async(&path, directory_id)
                        .await
                        .ok()
                } else {
                    None
                }
            })
            .buffer_unordered(32) // Process up to 32 shortened symlinks concurrently
            .filter_map(|result| async move { result })
            .collect()
            .await;

        let mut symlinks = regular_results;
        symlinks.extend(shortened_results);

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
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                VaultOperationError::Filename(e) => VaultWriteError::Filename(e),
                VaultOperationError::InvalidVaultStructure { reason, context } => {
                    VaultWriteError::DirectoryNotFound {
                        name: reason,
                        context: Box::new(context),
                    }
                }
                _ => VaultWriteError::DirectoryNotFound {
                    name: directory_id.as_str().to_string(),
                    context: Box::new(VaultOpContext::new().with_dir_id(directory_id.as_str())),
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
                context: Box::new(VaultOpContext::new()
                    .with_filename(name)
                    .with_dir_id(directory_id.as_str())),
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
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                VaultOperationError::Filename(e) => VaultWriteError::Filename(e),
                _ => VaultWriteError::DirectoryNotFound {
                    name: directory_id.as_str().to_string(),
                    context: Box::new(VaultOpContext::new().with_dir_id(directory_id.as_str())),
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
            context: Box::new(VaultOpContext::new()
                .with_filename(name)
                .with_dir_id(directory_id.as_str())),
        })
    }

    /// Rename a symlink within the same directory.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory ID containing the symlink
    /// * `old_name` - Current name of the symlink
    /// * `new_name` - New name for the symlink
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source symlink doesn't exist
    /// - A symlink with the new name already exists
    /// - IO error during rename
    #[instrument(level = "info", skip(self), fields(dir_id = %directory_id.as_str(), old_name = %old_name, new_name = %new_name))]
    pub async fn rename_symlink(
        &self,
        directory_id: &DirId,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Renaming symlink in vault");

        let ctx = VaultOpContext::new()
            .with_filename(old_name)
            .with_dir_id(directory_id.as_str());

        // Same name is a no-op
        if old_name == new_name {
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(ctx) });
        }

        // Acquire directory write lock
        let _guard = self.lock_manager.directory_write(directory_id).await;
        trace!("Acquired directory write lock for rename_symlink");

        // Find source symlink
        let source_info = self
            .find_symlink_unlocked(directory_id, old_name)
            .await
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                other => VaultWriteError::Io {
                    source: std::io::Error::other(other.to_string()),
                    context: Box::new(ctx.clone()),
                },
            })?
            .ok_or_else(|| VaultWriteError::FileNotFound {
                filename: old_name.to_string(),
                context: Box::new(ctx.clone()),
            })?;

        // Check that target doesn't exist
        if self.find_symlink_unlocked(directory_id, new_name).await?.is_some() {
            return Err(VaultWriteError::SymlinkAlreadyExists {
                name: new_name.to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(new_name)
                    .with_dir_id(directory_id.as_str())),
            });
        }

        let dir_path = self.calculate_directory_storage_path(directory_id)?;

        // Read the symlink target data (encrypted, can be copied as-is)
        let symlink_data = fs::read(source_info.encrypted_path.join("symlink.c9r"))
            .await
            .map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
            })?;

        // Encrypt new filename
        let new_encrypted_name = encrypt_filename(new_name, directory_id.as_str(), &self.master_key)?;
        let new_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Create destination (before delete for crash safety)
        let new_symlink_dir = if new_is_long {
            let shortened_hash = create_c9s_filename(&new_encrypted_name);
            let new_dir = dir_path.join(format!("{shortened_hash}.c9s"));
            fs::create_dir_all(&new_dir).await?;
            fs::write(new_dir.join("name.c9s"), &new_encrypted_name).await?;
            new_dir
        } else {
            let new_dir = dir_path.join(format!("{new_encrypted_name}.c9r"));
            fs::create_dir_all(&new_dir).await?;
            new_dir
        };

        // Write symlink target
        fs::write(new_symlink_dir.join("symlink.c9r"), &symlink_data).await?;

        // Delete source
        fs::remove_dir_all(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path)),
        })?;

        info!("Symlink renamed successfully");
        Ok(())
    }

    /// Move and rename a symlink to a different directory.
    ///
    /// # Arguments
    ///
    /// * `src_dir_id` - Source directory ID
    /// * `src_name` - Source symlink name
    /// * `dest_dir_id` - Destination directory ID
    /// * `dest_name` - Destination symlink name
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Source symlink not found
    /// - Destination symlink already exists
    /// - IO error during move
    #[instrument(level = "info", skip(self), fields(src_dir_id = %src_dir_id.as_str(), src_name = %src_name, dest_dir_id = %dest_dir_id.as_str(), dest_name = %dest_name))]
    pub async fn move_and_rename_symlink(
        &self,
        src_dir_id: &DirId,
        src_name: &str,
        dest_dir_id: &DirId,
        dest_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Moving and renaming symlink in vault");

        let src_ctx = VaultOpContext::new()
            .with_filename(src_name)
            .with_dir_id(src_dir_id.as_str());

        // Same directory and same name is a no-op
        if src_dir_id == dest_dir_id && src_name == dest_name {
            return Err(VaultWriteError::SameSourceAndDestination { context: Box::new(src_ctx) });
        }

        // Same directory? Use rename instead
        if src_dir_id == dest_dir_id {
            return self.rename_symlink(src_dir_id, src_name, dest_name).await;
        }

        // Acquire directory write locks in consistent order to prevent deadlocks
        let _dir_guards = self
            .lock_manager
            .lock_directories_write_ordered(&[src_dir_id, dest_dir_id])
            .await;
        trace!("Acquired directory write locks for move_and_rename_symlink");

        // Find source symlink
        let source_info = self
            .find_symlink_unlocked(src_dir_id, src_name)
            .await
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context: Box::new(context) },
                other => VaultWriteError::Io {
                    source: std::io::Error::other(other.to_string()),
                    context: Box::new(src_ctx.clone()),
                },
            })?
            .ok_or_else(|| VaultWriteError::FileNotFound {
                filename: src_name.to_string(),
                context: Box::new(src_ctx.clone()),
            })?;

        // Check that target doesn't exist
        if self.find_symlink_unlocked(dest_dir_id, dest_name).await?.is_some() {
            return Err(VaultWriteError::SymlinkAlreadyExists {
                name: dest_name.to_string(),
                context: Box::new(VaultOpContext::new()
                    .with_filename(dest_name)
                    .with_dir_id(dest_dir_id.as_str())),
            });
        }

        // Ensure destination directory exists
        let dest_storage_path = self.calculate_directory_storage_path(dest_dir_id)?;
        fs::create_dir_all(&dest_storage_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&dest_storage_path)),
        })?;

        // Read the symlink target data (encrypted, can be copied as-is since it's not
        // encrypted with the parent dir ID)
        let symlink_data = fs::read(source_info.encrypted_path.join("symlink.c9r"))
            .await
            .map_err(|e| VaultWriteError::Io {
                source: e,
                context: Box::new(src_ctx.clone().with_encrypted_path(&source_info.encrypted_path)),
            })?;

        // Encrypt filename with NEW directory ID
        let new_encrypted_name = encrypt_filename(dest_name, dest_dir_id.as_str(), &self.master_key)?;
        let dest_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Create destination (before delete for crash safety)
        let new_symlink_dir = if dest_is_long {
            let shortened_hash = create_c9s_filename(&new_encrypted_name);
            let new_dir = dest_storage_path.join(format!("{shortened_hash}.c9s"));
            fs::create_dir_all(&new_dir).await?;
            fs::write(new_dir.join("name.c9s"), &new_encrypted_name).await?;
            new_dir
        } else {
            let new_dir = dest_storage_path.join(format!("{new_encrypted_name}.c9r"));
            fs::create_dir_all(&new_dir).await?;
            new_dir
        };

        // Write symlink target
        fs::write(new_symlink_dir.join("symlink.c9r"), &symlink_data).await?;

        // Delete source
        fs::remove_dir_all(&source_info.encrypted_path).await.map_err(|e| VaultWriteError::Io {
            source: e,
            context: Box::new(VaultOpContext::new().with_encrypted_path(&source_info.encrypted_path)),
        })?;

        info!("Symlink moved and renamed successfully");
        Ok(())
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

/// Change the vault password asynchronously.
///
/// This is a standalone async function that changes the vault password by:
/// 1. Reading the existing masterkey file
/// 2. Unlocking with the old passphrase
/// 3. Re-wrapping the keys with the new passphrase
/// 4. Atomically writing the new masterkey file
///
/// The master keys (AES and MAC) never change - only the key encryption key (KEK)
/// derived from the passphrase is replaced.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `old_passphrase` - Current passphrase (for unlocking)
/// * `new_passphrase` - New passphrase (for re-wrapping)
///
/// # Errors
///
/// Returns an error if:
/// - The vault cannot be read
/// - The old passphrase is incorrect
/// - The new masterkey file cannot be written
///
/// # Example
///
/// ```ignore
/// change_password_async(Path::new("my_vault"), "old_password", "new_password").await?;
/// ```
#[instrument(level = "info", skip(old_passphrase, new_passphrase), fields(vault_path = %vault_path.display()))]
pub async fn change_password_async(
    vault_path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<(), ChangePasswordAsyncError> {
    use crate::vault::master_key::change_password;

    let masterkey_dir = vault_path.join("masterkey");
    let masterkey_path = masterkey_dir.join("masterkey.cryptomator");

    // Clone values for the blocking task
    let path = masterkey_path.clone();
    let old_pw = old_passphrase.to_string();
    let new_pw = new_passphrase.to_string();

    // Run crypto operations in blocking task (scrypt is CPU-intensive)
    let new_content = tokio::task::spawn_blocking(move || {
        change_password(&path, &old_pw, &new_pw)
    })
    .await
    .map_err(|e| ChangePasswordAsyncError::TaskJoin(e.to_string()))??;

    // Atomic write: write to temp file, then rename
    let temp_path = masterkey_dir.join("masterkey.cryptomator.tmp");
    fs::write(&temp_path, &new_content).await?;
    fs::rename(&temp_path, &masterkey_path).await?;

    info!("Vault password changed successfully");
    Ok(())
}

/// Errors that can occur when changing the vault password asynchronously.
#[derive(Error, Debug)]
pub enum ChangePasswordAsyncError {
    #[error("Password change failed: {0}")]
    ChangePassword(#[from] crate::vault::master_key::ChangePasswordError),

    #[error("Failed to write new masterkey file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Task join error: {0}")]
    TaskJoin(String),
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
