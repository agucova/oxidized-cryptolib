//! High-level synchronous vault operations combining directory and file functionality.
//!
//! This module provides convenient APIs for common Cryptomator vault operations
//! that are suitable for CLI tools and blocking contexts. For async/Tokio contexts,
//! see [`VaultOperationsAsync`](super::operations_async::VaultOperationsAsync).
//!
//! # Architecture
//!
//! `VaultOperations` delegates pure operations (path calculation, encryption, decryption)
//! to [`VaultCore`], sharing this logic with the async implementation.
//! I/O operations use `std::fs` directly.
//!
//! # Key Methods
//!
//! - **Listing**: [`list_files`](VaultOperations::list_files), [`list_directories`](VaultOperations::list_directories)
//! - **Lookup**: [`find_file`](VaultOperations::find_file), [`find_directory`](VaultOperations::find_directory) - O(1) lookups by name
//! - **Read/Write**: [`read_file`](VaultOperations::read_file), [`write_file`](VaultOperations::write_file)
//! - **Directories**: [`create_directory`](VaultOperations::create_directory), [`delete_directory`](VaultOperations::delete_directory)
//! - **Path resolution**: [`resolve_path`](VaultOperations::resolve_path)
//!
//! # Observability
//!
//! All key operations are instrumented with `tracing` spans and events to enable
//! integration with logging infrastructure and debugging of performance issues.
//! Sensitive parameters (master keys, file contents) are automatically skipped.
//!
//! # Reference Implementation
//!
//! - Java: [`CryptoFileSystemProvider`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoFileSystemProvider.java)
//!   provides the NIO FileSystemProvider implementation
//! - Java: [`CryptoFileSystemImpl`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoFileSystemImpl.java)
//!   implements the FileSystem interface with encryption
//! - Java: [`CryptoPathMapper`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoPathMapper.java)
//!   handles mapping between cleartext and ciphertext paths

use crate::{
    crypto::keys::MasterKey,
    fs::file::{DecryptedFile, FileContext},
    fs::name::{create_c9s_filename, decrypt_filename, decrypt_parent_dir_id, encrypt_filename, hash_dir_id, NameError},
    fs::symlink::{decrypt_symlink_target, encrypt_symlink_target, SymlinkError},
    vault::config::{extract_master_key, validate_vault_claims, CipherCombo, VaultError},
    vault::ops::{calculate_directory_lookup_paths, calculate_file_lookup_paths, calculate_symlink_lookup_paths, VaultCore},
    vault::path::{DirId, EntryType, VaultPath},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tracing::{debug, info, instrument, trace, warn};

/// Context for vault operations, providing debugging information.
#[derive(Debug, Clone, Default)]
pub struct VaultOpContext {
    /// The cleartext filename (if applicable)
    pub filename: Option<String>,
    /// The directory ID where the operation is occurring
    pub dir_id: Option<String>,
    /// The vault path being operated on
    pub vault_path: Option<String>,
    /// The encrypted path on disk
    pub encrypted_path: Option<PathBuf>,
}

impl VaultOpContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new boxed context (convenience method for reduced allocations in error paths)
    pub fn boxed() -> Box<Self> {
        Box::new(Self::default())
    }

    pub fn with_filename(mut self, filename: impl Into<String>) -> Self {
        self.filename = Some(filename.into());
        self
    }

    pub fn with_dir_id(mut self, dir_id: impl AsRef<str>) -> Self {
        let id = dir_id.as_ref();
        self.dir_id = Some(if id.is_empty() { "<root>".to_string() } else { id.to_string() });
        self
    }

    pub fn with_vault_path(mut self, path: impl Into<String>) -> Self {
        self.vault_path = Some(path.into());
        self
    }

    pub fn with_encrypted_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.encrypted_path = Some(path.into());
        self
    }

    /// Convert this context into a Box (for use in error types)
    #[inline]
    pub fn into_box(self) -> Box<Self> {
        Box::new(self)
    }
}

impl std::fmt::Display for VaultOpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();

        if let Some(ref path) = self.vault_path {
            parts.push(format!("path '{path}'"));
        }
        if let Some(ref filename) = self.filename {
            parts.push(format!("file '{filename}'"));
        }
        if let Some(ref dir_id) = self.dir_id {
            let display_id = if dir_id.len() > 12 {
                format!("{}...", &dir_id[..12])
            } else {
                dir_id.clone()
            };
            parts.push(format!("in directory {display_id}"));
        }
        if let Some(ref enc_path) = self.encrypted_path {
            parts.push(format!("at {:?}", enc_path.display()));
        }

        if parts.is_empty() {
            write!(f, "(no context)")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

#[derive(Error, Debug)]
pub enum VaultOperationError {
    #[error("IO error for {context}: {source}")]
    Io {
        #[source]
        source: std::io::Error,
        context: VaultOpContext,
    },

    #[error("File decryption error: {0}")]
    FileDecryption(#[from] crate::fs::file::FileError),

    #[error("File content decryption error: {0}")]
    FileContentDecryption(#[from] crate::fs::file::FileDecryptionError),

    #[error("Filename error: {0}")]
    Filename(#[from] NameError),

    #[error("Directory '{name}' not found {context}")]
    DirectoryNotFound {
        name: String,
        context: VaultOpContext,
    },

    #[error("Invalid vault structure for {context}: {reason}")]
    InvalidVaultStructure {
        reason: String,
        context: VaultOpContext,
    },

    #[error("Path not found: '{path}'")]
    PathNotFound { path: String },

    #[error("Expected file but found directory: '{path}'")]
    NotAFile { path: String },

    #[error("Expected directory but found file: '{path}'")]
    NotADirectory { path: String },

    #[error("Empty path provided")]
    EmptyPath,

    #[error("File '{filename}' not found {context}")]
    FileNotFound {
        filename: String,
        context: VaultOpContext,
    },

    #[error("Symlink error: {0}")]
    Symlink(Box<SymlinkError>),

    #[error("Symlink '{name}' not found {context}")]
    SymlinkNotFound {
        name: String,
        context: VaultOpContext,
    },

    #[error("Not a symlink: '{path}'")]
    NotASymlink { path: String },

    /// Streaming operation error (async only)
    #[cfg(feature = "async")]
    #[error("Streaming error for {context}: {source}")]
    Streaming {
        #[source]
        source: Box<crate::fs::streaming::StreamingError>,
        context: VaultOpContext,
    },
}

impl From<SymlinkError> for VaultOperationError {
    fn from(e: SymlinkError) -> Self {
        VaultOperationError::Symlink(Box::new(e))
    }
}

impl From<std::io::Error> for VaultOperationError {
    fn from(source: std::io::Error) -> Self {
        VaultOperationError::Io {
            source,
            context: VaultOpContext::new(),
        }
    }
}

/// Errors that can occur during vault write operations
#[derive(Error, Debug)]
pub enum VaultWriteError {
    #[error("IO error for {context}: {source}")]
    Io {
        #[source]
        source: std::io::Error,
        context: VaultOpContext,
    },

    #[error("File encryption error: {0}")]
    Encryption(#[from] crate::fs::file::FileEncryptionError),

    #[error("Filename error: {0}")]
    Filename(#[from] NameError),

    #[error("Directory '{name}' not found {context}")]
    DirectoryNotFound {
        name: String,
        context: VaultOpContext,
    },

    #[error("File '{filename}' already exists {context}")]
    FileAlreadyExists {
        filename: String,
        context: VaultOpContext,
    },

    #[error("Directory '{name}' already exists {context}")]
    DirectoryAlreadyExists {
        name: String,
        context: VaultOpContext,
    },

    #[error("Directory not empty: {context}")]
    DirectoryNotEmpty { context: VaultOpContext },

    #[error("Atomic write failed for {context}: {reason}")]
    AtomicWriteFailed {
        reason: String,
        context: VaultOpContext,
    },

    #[error("File '{filename}' not found {context}")]
    FileNotFound {
        filename: String,
        context: VaultOpContext,
    },

    #[error("Source and destination are the same: {context}")]
    SameSourceAndDestination { context: VaultOpContext },

    #[error("Symlink error: {0}")]
    Symlink(Box<SymlinkError>),

    #[error("Symlink '{name}' already exists {context}")]
    SymlinkAlreadyExists {
        name: String,
        context: VaultOpContext,
    },

    #[error("Path already exists: {path}")]
    PathExists { path: String },

    /// Streaming operation error (async only)
    #[cfg(feature = "async")]
    #[error("Streaming error for {context}: {source}")]
    Streaming {
        #[source]
        source: Box<crate::fs::streaming::StreamingError>,
        context: VaultOpContext,
    },
}

impl From<SymlinkError> for VaultWriteError {
    fn from(e: SymlinkError) -> Self {
        VaultWriteError::Symlink(Box::new(e))
    }
}

impl From<std::io::Error> for VaultWriteError {
    fn from(source: std::io::Error) -> Self {
        VaultWriteError::Io {
            source,
            context: VaultOpContext::new(),
        }
    }
}

/// Statistics returned from recursive delete operations
#[derive(Debug, Default, Clone, Copy)]
pub struct DeleteStats {
    /// Number of files deleted
    pub files_deleted: usize,
    /// Number of directories deleted
    pub directories_deleted: usize,
}

impl From<VaultOperationError> for VaultWriteError {
    fn from(err: VaultOperationError) -> Self {
        match err {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            VaultOperationError::Filename(e) => VaultWriteError::Filename(e),
            VaultOperationError::DirectoryNotFound { name, context } => {
                VaultWriteError::DirectoryNotFound { name, context }
            }
            VaultOperationError::FileDecryption(e) => VaultWriteError::Io {
                source: std::io::Error::other(e.to_string()),
                context: VaultOpContext::new(),
            },
            VaultOperationError::InvalidVaultStructure { reason, context } => VaultWriteError::Io {
                source: std::io::Error::other(reason),
                context,
            },
            VaultOperationError::PathNotFound { path } => VaultWriteError::FileNotFound {
                filename: path,
                context: VaultOpContext::new(),
            },
            VaultOperationError::NotAFile { path } => VaultWriteError::Io {
                source: std::io::Error::other(format!("Expected file: {path}")),
                context: VaultOpContext::new().with_vault_path(path),
            },
            VaultOperationError::NotADirectory { path } => VaultWriteError::DirectoryNotFound {
                name: path.clone(),
                context: VaultOpContext::new().with_vault_path(path),
            },
            VaultOperationError::EmptyPath => VaultWriteError::Io {
                source: std::io::Error::other("Empty path provided"),
                context: VaultOpContext::new(),
            },
            VaultOperationError::FileNotFound { filename, context } => {
                VaultWriteError::FileNotFound { filename, context }
            }
            VaultOperationError::Symlink(e) => VaultWriteError::Symlink(e),
            VaultOperationError::SymlinkNotFound { name, context } => {
                VaultWriteError::FileNotFound {
                    filename: name,
                    context,
                }
            }
            VaultOperationError::NotASymlink { path } => VaultWriteError::Io {
                source: std::io::Error::other(format!("Not a symlink: {path}")),
                context: VaultOpContext::new().with_vault_path(path),
            },
            VaultOperationError::FileContentDecryption(e) => VaultWriteError::Io {
                source: std::io::Error::other(e.to_string()),
                context: VaultOpContext::new(),
            },
            #[cfg(feature = "async")]
            VaultOperationError::Streaming { source, context } => {
                VaultWriteError::Streaming { source, context }
            }
        }
    }
}

/// Information about a file in the vault
#[derive(Debug, Clone)]
pub struct VaultFileInfo {
    /// Decrypted filename
    pub name: String,
    /// Encrypted filename (as stored on disk)
    pub encrypted_name: String,
    /// Full path to the encrypted file
    pub encrypted_path: PathBuf,
    /// Size of the encrypted file
    pub encrypted_size: u64,
    /// Whether this is a shortened name (.c9s)
    pub is_shortened: bool,
}

/// Information about a directory in the vault
#[derive(Debug, Clone)]
pub struct VaultDirectoryInfo {
    /// Decrypted directory name
    pub name: String,
    /// Directory ID
    pub directory_id: DirId,
    /// Encrypted path on disk
    pub encrypted_path: PathBuf,
    /// Parent directory ID
    pub parent_directory_id: DirId,
}

/// Information about a symlink in the vault
#[derive(Debug, Clone)]
pub struct VaultSymlinkInfo {
    /// Decrypted symlink name
    pub name: String,
    /// Target path the symlink points to
    pub target: String,
    /// Encrypted path on disk
    pub encrypted_path: PathBuf,
    /// Whether this is a shortened name (.c9s)
    pub is_shortened: bool,
}

/// A unified directory entry that can be a file, directory, or symlink.
///
/// This provides a more ergonomic API for listing directory contents,
/// replacing the need to call `list_files()`, `list_directories()`, and
/// `list_symlinks()` separately.
///
/// # Examples
///
/// ```ignore
/// for entry in vault_ops.list("Documents")? {
///     match entry {
///         DirEntry::File(info) => println!("File: {}", info.name),
///         DirEntry::Directory(info) => println!("Dir: {}", info.name),
///         DirEntry::Symlink(info) => println!("Link: {} -> {}", info.name, info.target),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum DirEntry {
    /// A regular file
    File(VaultFileInfo),
    /// A directory
    Directory(VaultDirectoryInfo),
    /// A symbolic link
    Symlink(VaultSymlinkInfo),
}

impl DirEntry {
    /// Get the name of this entry.
    pub fn name(&self) -> &str {
        match self {
            DirEntry::File(info) => &info.name,
            DirEntry::Directory(info) => &info.name,
            DirEntry::Symlink(info) => &info.name,
        }
    }

    /// Get the type of this entry.
    pub fn entry_type(&self) -> EntryType {
        match self {
            DirEntry::File(_) => EntryType::File,
            DirEntry::Directory(_) => EntryType::Directory,
            DirEntry::Symlink(_) => EntryType::Symlink,
        }
    }

    /// Returns `true` if this is a file.
    pub fn is_file(&self) -> bool {
        matches!(self, DirEntry::File(_))
    }

    /// Returns `true` if this is a directory.
    pub fn is_directory(&self) -> bool {
        matches!(self, DirEntry::Directory(_))
    }

    /// Returns `true` if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self, DirEntry::Symlink(_))
    }

    /// Get the file info if this is a file.
    pub fn as_file(&self) -> Option<&VaultFileInfo> {
        match self {
            DirEntry::File(info) => Some(info),
            _ => None,
        }
    }

    /// Get the directory info if this is a directory.
    pub fn as_directory(&self) -> Option<&VaultDirectoryInfo> {
        match self {
            DirEntry::Directory(info) => Some(info),
            _ => None,
        }
    }

    /// Get the symlink info if this is a symlink.
    pub fn as_symlink(&self) -> Option<&VaultSymlinkInfo> {
        match self {
            DirEntry::Symlink(info) => Some(info),
            _ => None,
        }
    }
}

/// Information about a recovered directory from dirid.c9r backup files.
///
/// This struct is returned by `recover_directory_ids()` and contains
/// the recovered directory ID from a `dirid.c9r` backup file.
///
/// **Note**: The `dirid.c9r` backup file stores the directory's OWN ID,
/// not the parent's ID. This was verified by examining the Java reference
/// implementation (`DirectoryIdBackup.java`). Recovery can restore the
/// directory ID but cannot automatically restore parent-child relationships.
#[derive(Debug, Clone)]
pub struct RecoveredDirectoryInfo {
    /// The directory's own ID (recovered from dir.c9r)
    pub directory_id: DirId,
    /// Parent directory ID (recovered from dirid.c9r)
    pub parent_directory_id: DirId,
    /// Path to the encrypted directory on disk
    pub encrypted_path: PathBuf,
}

/// High-level interface for vault operations.
///
/// # Reference Implementation
///
/// - Java: [`CryptoFileSystemImpl`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoFileSystemImpl.java)
///   implements high-level file system operations
/// - Java: [`CryptoPathMapper`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoPathMapper.java)
///   maps cleartext paths to ciphertext paths on disk
pub struct VaultOperations {
    /// Shared core state (path, cipher combo, shortening threshold).
    core: VaultCore,
    /// The master key for encryption/decryption operations.
    master_key: MasterKey,
}

/// Default shortening threshold for filenames (220 characters)
pub use crate::vault::config::DEFAULT_SHORTENING_THRESHOLD;

impl VaultOperations {
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
    /// let ops = VaultOperations::open(Path::new("my_vault"), "password")?;
    /// let files = ops.list_files(&DirId::root())?;
    /// ```
    #[instrument(level = "info", skip(password), fields(vault_path = %vault_path.display()))]
    pub fn open(vault_path: &Path, password: &str) -> Result<Self, VaultError> {
        // Extract master key (validates password)
        let master_key = extract_master_key(vault_path, password)?;

        // Read and validate vault config to get cipher combo and shortening threshold
        let vault_config_path = vault_path.join("vault.cryptomator");
        let vault_config_jwt = fs::read_to_string(&vault_config_path)?;
        let claims = validate_vault_claims(&vault_config_jwt, &master_key)?;

        let cipher_combo = claims.cipher_combo().expect("cipher combo already validated");
        let shortening_threshold = claims.shortening_threshold();

        info!(
            cipher_combo = ?cipher_combo,
            shortening_threshold = shortening_threshold,
            "Vault opened successfully"
        );

        Ok(Self::with_options(vault_path, master_key, shortening_threshold, cipher_combo))
    }

    /// Create a new VaultOperations instance with default shortening threshold (220) and SIV_GCM cipher combo.
    ///
    /// **Note:** Prefer [`open()`](Self::open) for opening existing vaults, as it
    /// automatically reads the correct cipher combo from the vault configuration.
    /// Use this method only when you need manual control over the configuration.
    #[instrument(level = "info", skip(master_key), fields(vault_path = %vault_path.display()))]
    pub fn new(vault_path: &Path, master_key: MasterKey) -> Self {
        Self::with_options(vault_path, master_key, DEFAULT_SHORTENING_THRESHOLD, CipherCombo::SivGcm)
    }

    /// Create a new VaultOperations instance with a custom shortening threshold
    ///
    /// The shortening threshold determines when encrypted filenames are shortened
    /// to use the .c9s format. Filenames longer than this threshold will be
    /// replaced with a SHA-1 hash.
    ///
    /// # Arguments
    /// * `vault_path` - Path to the vault root directory
    /// * `master_key` - The master key for encryption/decryption
    /// * `shortening_threshold` - Maximum length for encrypted filenames before shortening
    #[instrument(level = "info", skip(master_key), fields(vault_path = %vault_path.display(), shortening_threshold = shortening_threshold))]
    pub fn with_shortening_threshold(
        vault_path: &Path,
        master_key: MasterKey,
        shortening_threshold: usize,
    ) -> Self {
        Self::with_options(vault_path, master_key, shortening_threshold, CipherCombo::SivGcm)
    }

    /// Create a new VaultOperations instance with full configuration options
    ///
    /// # Arguments
    /// * `vault_path` - Path to the vault root directory
    /// * `master_key` - The master key for encryption/decryption
    /// * `shortening_threshold` - Maximum length for encrypted filenames before shortening
    /// * `cipher_combo` - The cipher combination used by this vault (SIV_GCM or SIV_CTRMAC)
    #[instrument(level = "info", skip(master_key), fields(vault_path = %vault_path.display(), shortening_threshold = shortening_threshold, cipher_combo = ?cipher_combo))]
    pub fn with_options(
        vault_path: &Path,
        master_key: MasterKey,
        shortening_threshold: usize,
        cipher_combo: CipherCombo,
    ) -> Self {
        info!("Initializing VaultOperations");
        Self {
            core: VaultCore::with_shortening_threshold(
                vault_path.to_path_buf(),
                cipher_combo,
                shortening_threshold,
            ),
            master_key,
        }
    }

    /// Returns the shortening threshold for encrypted filenames
    pub fn shortening_threshold(&self) -> usize {
        self.core.shortening_threshold()
    }

    /// Returns a reference to the vault path
    pub fn vault_path(&self) -> &Path {
        self.core.vault_path()
    }

    /// Returns a reference to the master key
    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    /// Returns the cipher combination used by this vault
    pub fn cipher_combo(&self) -> CipherCombo {
        self.core.cipher_combo()
    }

    /// Returns a reference to the VaultCore for shared operations
    pub fn core(&self) -> &VaultCore {
        &self.core
    }

    /// Decrypt a file using the vault's cipher combo.
    ///
    /// This method reads the file and dispatches to the appropriate decryption
    /// method based on the vault's cipher combo configuration.
    fn decrypt_file_internal(&self, path: &Path) -> Result<DecryptedFile, VaultOperationError> {
        let context = FileContext::new().with_path(path);
        let encrypted = fs::read(path).map_err(|e| VaultOperationError::Io {
            source: e,
            context: VaultOpContext::new().with_encrypted_path(path),
        })?;

        self.core.cipher_combo()
            .decrypt_file_with_context(&encrypted, &self.master_key, context)
            .map_err(VaultOperationError::FileContentDecryption)
    }

    /// Calculate the storage path for a directory given its ID
    ///
    /// # Errors
    /// Returns `VaultOperationError::FilenameEncryption` if hashing the directory ID fails.
    #[instrument(level = "trace", skip(self), fields(dir_id = %dir_id.as_str()))]
    pub fn calculate_directory_storage_path(&self, dir_id: &DirId) -> Result<PathBuf, VaultOperationError> {
        let hashed = hash_dir_id(dir_id.as_str(), &self.master_key)?;
        let hash_chars: Vec<char> = hashed.chars().collect();

        if hash_chars.len() < 32 {
            return Err(VaultOperationError::InvalidVaultStructure {
                reason: format!("Hashed directory ID is too short: {}", hash_chars.len()),
                context: VaultOpContext::new().with_dir_id(dir_id.as_str()),
            });
        }

        let first_two: String = hash_chars[0..2].iter().collect();
        let remaining: String = hash_chars[2..32].iter().collect();

        Ok(self.core.vault_path().join("d").join(&first_two).join(&remaining))
    }
    
    /// List all files in a directory (by directory ID)
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub fn list_files(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultFileInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id)?;
        trace!(path = %dir_path.display(), "Calculated storage path for list_files");

        if !dir_path.exists() {
            debug!("Directory storage path does not exist, returning empty file list");
            return Ok(Vec::new()); // Empty directory
        }

        let mut files = Vec::new();

        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            // Skip special files
            if file_name == "dirid.c9r" {
                continue;
            }

            // Skip .c9r directories (these are handled by list_directories)
            if path.is_dir() && file_name.ends_with(".c9r") {
                continue;
            }

            // Skip other directories that aren't .c9s
            if path.is_dir() && !file_name.ends_with(".c9s") {
                continue;
            }

            if file_name.ends_with(".c9r") {
                match decrypt_filename(&file_name, directory_id.as_str(), &self.master_key) {
                    Ok(decrypted_name) => {
                        let metadata = fs::metadata(&path)?;
                        files.push(VaultFileInfo {
                            name: decrypted_name,
                            encrypted_name: file_name,
                            encrypted_path: path,
                            encrypted_size: metadata.len(),
                            is_shortened: false,
                        });
                    }
                    Err(e) => {
                        warn!(encrypted_name = %file_name, error = %e, "Failed to decrypt filename");
                    }
                }
            } else if file_name.ends_with(".c9s") && path.is_dir() {
                // Handle shortened names
                if let Ok(info) = self.read_shortened_file_info(&path, directory_id) {
                    files.push(info);
                }
            }
        }

        debug!(file_count = files.len(), "Listed files in directory");
        Ok(files)
    }

    /// List all subdirectories in a directory (by directory ID)
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub fn list_directories(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultDirectoryInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id)?;
        trace!(path = %dir_path.display(), "Calculated storage path for list_directories");

        if !dir_path.exists() {
            debug!("Directory storage path does not exist, returning empty directory list");
            return Ok(Vec::new()); // Empty directory
        }

        let mut directories = Vec::new();

        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() && file_name.ends_with(".c9r") {
                // This is a regular directory
                trace!(encrypted_name = %file_name, "Processing directory entry");
                if let Ok(dir_info) = self.read_directory_info(&path, &file_name, directory_id) {
                    directories.push(dir_info);
                }
            } else if path.is_dir() && file_name.ends_with(".c9s") {
                // This might be a shortened directory
                trace!(shortened_name = %file_name, "Processing shortened directory entry");
                if path.join("dir.c9r").exists()
                    && let Ok(dir_info) = self.read_shortened_directory_info(&path, directory_id)
                {
                    directories.push(dir_info);
                }
            }
        }

        debug!(directory_count = directories.len(), "Listed subdirectories");
        Ok(directories)
    }

    /// List all symlinks in a directory (by directory ID)
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub fn list_symlinks(
        &self,
        directory_id: &DirId,
    ) -> Result<Vec<VaultSymlinkInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id)?;
        trace!(path = %dir_path.display(), "Calculated storage path for list_symlinks");

        if !dir_path.exists() {
            debug!("Directory storage path does not exist, returning empty symlink list");
            return Ok(Vec::new());
        }

        let mut symlinks = Vec::new();

        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() && file_name.ends_with(".c9r") {
                // Check if this is a symlink (has symlink.c9r)
                let symlink_file = path.join("symlink.c9r");
                if symlink_file.exists() {
                    trace!(encrypted_name = %file_name, "Processing symlink entry");
                    if let Ok(info) = self.read_symlink_info(&path, &file_name, directory_id, false) {
                        symlinks.push(info);
                    }
                }
            } else if path.is_dir() && file_name.ends_with(".c9s") {
                // Check if this is a shortened symlink
                let symlink_file = path.join("symlink.c9r");
                if symlink_file.exists() {
                    trace!(shortened_name = %file_name, "Processing shortened symlink entry");
                    if let Ok(info) = self.read_shortened_symlink_info(&path, directory_id) {
                        symlinks.push(info);
                    }
                }
            }
        }

        debug!(symlink_count = symlinks.len(), "Listed symlinks in directory");
        Ok(symlinks)
    }

    /// List all entries in a directory (files, directories, and symlinks).
    ///
    /// This is a convenience method that combines `list_files()`, `list_directories()`,
    /// and `list_symlinks()` into a single call returning unified `DirEntry` values.
    ///
    /// # Arguments
    /// * `directory_id` - The directory ID to list
    ///
    /// # Returns
    /// A vector of `DirEntry` values representing all entries in the directory.
    ///
    /// # Examples
    /// ```ignore
    /// for entry in vault_ops.list(&dir_id)? {
    ///     println!("{}: {}", entry.entry_type(), entry.name());
    /// }
    /// ```
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str()))]
    pub fn list(&self, directory_id: &DirId) -> Result<Vec<DirEntry>, VaultOperationError> {
        let mut entries = Vec::new();

        // Collect files
        for file in self.list_files(directory_id)? {
            entries.push(DirEntry::File(file));
        }

        // Collect directories
        for dir in self.list_directories(directory_id)? {
            entries.push(DirEntry::Directory(dir));
        }

        // Collect symlinks
        for symlink in self.list_symlinks(directory_id)? {
            entries.push(DirEntry::Symlink(symlink));
        }

        debug!(entry_count = entries.len(), "Listed all entries in directory");
        Ok(entries)
    }

    /// List all entries at a given path.
    ///
    /// This is a path-based convenience wrapper around `list()` that accepts
    /// a path instead of a directory ID.
    ///
    /// # Arguments
    /// * `path` - A path within the vault like "Documents" or "Photos/Vacation"
    ///
    /// # Returns
    /// A vector of `DirEntry` values representing all entries in the directory.
    ///
    /// # Errors
    /// - `DirectoryNotFound` if the path doesn't exist or isn't a directory
    ///
    /// # Examples
    /// ```ignore
    /// for entry in vault_ops.list_by_path("Documents")? {
    ///     println!("{}: {}", entry.entry_type(), entry.name());
    /// }
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = %path.as_ref()))]
    pub fn list_by_path(&self, path: impl AsRef<str>) -> Result<Vec<DirEntry>, VaultOperationError> {
        let vault_path = VaultPath::new(path.as_ref());

        let dir_id = if vault_path.is_root() {
            DirId::root()
        } else {
            let (dir_id, is_dir) = self.resolve_path(vault_path.as_str())?;
            if !is_dir {
                return Err(VaultOperationError::NotADirectory {
                    path: vault_path.to_string(),
                });
            }
            dir_id
        };

        self.list(&dir_id)
    }

    // ========================================================================
    // Optimized Single-Entry Lookup Methods
    // ========================================================================

    /// Find a specific file by name without scanning the entire directory.
    ///
    /// This is significantly faster than `list_files()` for directories with many entries,
    /// as it directly checks the expected encrypted path rather than iterating all entries.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The directory to search in
    /// * `filename` - The cleartext filename to look for
    ///
    /// # Returns
    ///
    /// * `Ok(Some(info))` - File found
    /// * `Ok(None)` - File not found
    /// * `Err(...)` - I/O or encryption error
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), filename = %filename))]
    pub fn find_file(
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

        // Perform I/O to check if file exists
        match fs::metadata(&paths.content_path) {
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
    /// * `parent_directory_id` - The parent directory to search in
    /// * `dir_name` - The cleartext directory name to look for
    ///
    /// # Returns
    ///
    /// * `Ok(Some(info))` - Directory found
    /// * `Ok(None)` - Directory not found
    /// * `Err(...)` - I/O or encryption error
    #[instrument(level = "debug", skip(self), fields(parent_dir_id = %parent_directory_id.as_str(), dir_name = %dir_name))]
    pub fn find_directory(
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

        // Perform I/O to read directory ID from dir.c9r marker
        match fs::read_to_string(&paths.content_path) {
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
            // NotADirectory means the entry exists but is a file, not a directory
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
                trace!("Entry exists but is not a directory");
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

    /// Find a specific symlink by name without scanning the entire parent directory.
    ///
    /// This is significantly faster than `list_symlinks()` for directories with many entries,
    /// as it directly checks the expected encrypted path rather than iterating all entries.
    ///
    /// # Arguments
    ///
    /// * `directory_id` - The parent directory to search in
    /// * `name` - The cleartext symlink name to look for
    ///
    /// # Returns
    ///
    /// * `Ok(Some(info))` - Symlink found
    /// * `Ok(None)` - Symlink not found
    /// * `Err(...)` - I/O or encryption error
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), name = %name))]
    pub fn find_symlink(
        &self,
        directory_id: &DirId,
        name: &str,
    ) -> Result<Option<VaultSymlinkInfo>, VaultOperationError> {
        let storage_path = self.calculate_directory_storage_path(directory_id)?;

        // Encrypt the symlink name to get the expected path
        let encrypted_name = encrypt_filename(name, directory_id.as_str(), &self.master_key)?;

        // Calculate paths using shared helper
        let paths = calculate_symlink_lookup_paths(
            &storage_path,
            &encrypted_name,
            self.core.shortening_threshold(),
        );

        // Perform I/O to read symlink target from symlink.c9r
        match fs::read(&paths.content_path) {
            Ok(encrypted_data) => {
                let target = decrypt_symlink_target(&encrypted_data, &self.master_key)?;
                trace!(target_len = target.len(), shortened = paths.is_shortened, "Found symlink");
                Ok(Some(VaultSymlinkInfo {
                    name: name.to_string(),
                    target,
                    encrypted_path: paths.entry_path,
                    is_shortened: paths.is_shortened,
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                trace!(shortened = paths.is_shortened, "Symlink not found");
                Ok(None)
            }
            // NotADirectory means the entry_path exists but is a file, not a symlink
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
                trace!("Entry exists but is a file, not a symlink");
                Ok(None)
            }
            Err(e) => Err(VaultOperationError::Io {
                source: e,
                context: VaultOpContext::new()
                    .with_filename(name)
                    .with_dir_id(directory_id.as_str())
                    .with_encrypted_path(&paths.content_path),
            }),
        }
    }

    // ========================================================================
    // File Content Methods
    // ========================================================================

    /// Read a file's contents by providing the directory ID and filename
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), filename = %filename))]
    pub fn read_file(
        &self,
        directory_id: &DirId,
        filename: &str,
    ) -> Result<DecryptedFile, VaultOperationError> {
        // First, find the file
        debug!("Looking up file in directory");
        let files = self.list_files(directory_id)?;
        let file_info = files
            .into_iter()
            .find(|f| f.name == filename)
            .ok_or_else(|| {
                warn!("File not found in directory");
                VaultOperationError::FileNotFound {
                    filename: filename.to_string(),
                    context: VaultOpContext::new()
                        .with_filename(filename)
                        .with_dir_id(directory_id.as_str()),
                }
            })?;

        // Then decrypt it using the appropriate cipher combo
        debug!(encrypted_path = %file_info.encrypted_path.display(), encrypted_size = file_info.encrypted_size, cipher_combo = ?self.core.cipher_combo(), "Decrypting file");
        let decrypted = self.decrypt_file_internal(&file_info.encrypted_path)?;
        info!(decrypted_size = decrypted.content.len(), "File decrypted successfully");
        Ok(decrypted)
    }
    
    /// Get the full path for a file/directory by walking from root
    ///
    /// Returns the directory ID and whether it's a directory (vs file).
    #[instrument(level = "debug", skip(self), fields(path = %path))]
    pub fn resolve_path(&self, path: &str) -> Result<(DirId, bool), VaultOperationError> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        debug!(component_count = components.len(), "Resolving path");

        if components.is_empty() {
            debug!("Path is root directory");
            return Ok((DirId::root(), true)); // Root directory
        }

        let mut current_dir_id = DirId::root();
        let mut is_directory = true;

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            trace!(component = %component, depth = i, is_last = is_last, "Traversing path component");

            if is_last {
                // Use optimized lookup: check if it's a file first
                if self.find_file(&current_dir_id, component)?.is_some() {
                    trace!("Found file at path");
                    is_directory = false;
                    break;
                }
            }

            // Use optimized lookup for directory
            let dir = self
                .find_directory(&current_dir_id, component)?
                .ok_or_else(|| {
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

    // ==================== Path-based Convenience Methods ====================
    //
    // These methods accept relative paths like "docs/readme.txt" and internally
    // resolve them to (DirId, filename) pairs. This is more ergonomic for CLI
    // tools and simple use cases where callers don't need to cache directory IDs.

    /// Resolve a path to its parent directory ID and final component name.
    ///
    /// This is useful for file operations that need both the containing directory
    /// and the filename.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/readme.txt" or "/docs/readme.txt"
    ///
    /// # Returns
    /// A tuple of (parent_directory_id, filename)
    ///
    /// # Errors
    /// - `EmptyPath` if the path is empty or just "/"
    /// - `DirectoryNotFound` if any intermediate directory doesn't exist
    pub fn resolve_parent_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<(DirId, String), VaultOperationError> {
        let vault_path = VaultPath::new(path.as_ref());

        let (parent_path, filename) = vault_path
            .split()
            .ok_or(VaultOperationError::EmptyPath)?;

        // Walk to the parent directory
        let parent_dir_id = if parent_path.is_root() {
            DirId::root()
        } else {
            let (dir_id, is_dir) = self.resolve_path(parent_path.as_str())?;
            if !is_dir {
                return Err(VaultOperationError::NotADirectory {
                    path: parent_path.to_string(),
                });
            }
            dir_id
        };

        Ok((parent_dir_id, filename.to_string()))
    }

    /// Read a file by its path.
    ///
    /// This is a convenience wrapper around `read_file()` that accepts a path
    /// instead of (DirId, filename).
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/readme.txt"
    ///
    /// # Examples
    /// ```ignore
    /// let content = vault_ops.read_by_path("documents/report.txt")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn read_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<DecryptedFile, VaultOperationError> {
        let (dir_id, filename) = self.resolve_parent_path(path.as_ref())?;
        debug!(dir_id = %dir_id, filename = %filename, "Resolved path for read");
        self.read_file(&dir_id, &filename)
    }

    /// Write a file by its path.
    ///
    /// This is a convenience wrapper around `write_file()` that accepts a path
    /// instead of (DirId, filename).
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/readme.txt"
    /// * `content` - The file contents to write
    ///
    /// # Errors
    /// - `DirectoryNotFound` if the parent directory doesn't exist
    ///
    /// # Note
    /// This does NOT create parent directories automatically. Use
    /// `create_directory()` or `create_directory_by_path()` first if needed.
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.write_by_path("documents/report.txt", b"Hello, world!")?;
    /// ```
    #[instrument(level = "debug", skip(self, content), fields(path = path.as_ref(), content_len = content.len()))]
    pub fn write_by_path(
        &self,
        path: impl AsRef<str>,
        content: &[u8],
    ) -> Result<PathBuf, VaultWriteError> {
        let (dir_id, filename) = self.resolve_parent_path(path.as_ref())?;
        debug!(dir_id = %dir_id, filename = %filename, "Resolved path for write");
        self.write_file(&dir_id, &filename, content)
    }

    /// Delete a file by its path.
    ///
    /// This is a convenience wrapper around `delete_file()` that accepts a path
    /// instead of (DirId, filename).
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/readme.txt"
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.delete_by_path("documents/old_report.txt")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn delete_by_path(&self, path: impl AsRef<str>) -> Result<(), VaultWriteError> {
        let (dir_id, filename) = self.resolve_parent_path(path.as_ref())?;
        debug!(dir_id = %dir_id, filename = %filename, "Resolved path for delete");
        self.delete_file(&dir_id, &filename)
    }

    /// Get the type of an entry at the given path.
    ///
    /// Returns `Some(EntryType)` if the path exists, or `None` if it doesn't.
    ///
    /// # Arguments
    /// * `path` - A path within the vault like "docs/readme.txt" or "docs"
    ///
    /// # Returns
    /// - `Some(EntryType::File)` if a file exists at the path
    /// - `Some(EntryType::Directory)` if a directory exists at the path
    /// - `Some(EntryType::Symlink)` if a symlink exists at the path
    /// - `None` if nothing exists at the path
    ///
    /// # Examples
    /// ```ignore
    /// use oxidized_cryptolib::vault::path::EntryType;
    ///
    /// match vault_ops.entry_type("documents/report.txt") {
    ///     Some(EntryType::File) => println!("It's a file"),
    ///     Some(EntryType::Directory) => println!("It's a directory"),
    ///     Some(EntryType::Symlink) => println!("It's a symlink"),
    ///     None => println!("Path doesn't exist"),
    /// }
    /// ```
    #[instrument(level = "trace", skip(self), fields(path = %path.as_ref()))]
    pub fn entry_type(&self, path: impl AsRef<str>) -> Option<EntryType> {
        let vault_path = VaultPath::new(path.as_ref());

        if vault_path.is_root() {
            return Some(EntryType::Directory); // Root is always a directory
        }

        // Get the parent directory and the entry name
        let (parent_path, entry_name) = vault_path.split()?;

        // Resolve the parent directory
        let parent_dir_id = if parent_path.is_root() {
            DirId::root()
        } else {
            match self.resolve_path(parent_path.as_str()) {
                Ok((dir_id, true)) => dir_id,
                _ => return None, // Parent doesn't exist or isn't a directory
            }
        };

        // Check for symlink first (symlinks can have same name as files/dirs in theory)
        if let Ok(symlinks) = self.list_symlinks(&parent_dir_id)
            && symlinks.iter().any(|s| s.name == entry_name) {
                trace!(entry_type = "symlink", "Found symlink at path");
                return Some(EntryType::Symlink);
            }

        // Check for directory
        if let Ok(dirs) = self.list_directories(&parent_dir_id)
            && dirs.iter().any(|d| d.name == entry_name) {
                trace!(entry_type = "directory", "Found directory at path");
                return Some(EntryType::Directory);
            }

        // Check for file
        if let Ok(files) = self.list_files(&parent_dir_id)
            && files.iter().any(|f| f.name == entry_name) {
                trace!(entry_type = "file", "Found file at path");
                return Some(EntryType::File);
            }

        trace!("Path does not exist");
        None
    }

    /// Create a directory by its path.
    ///
    /// This is a convenience wrapper around `create_directory()` that accepts
    /// a path instead of (parent_dir_id, name).
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/new_folder"
    ///
    /// # Returns
    /// The newly created directory's ID
    ///
    /// # Errors
    /// - `DirectoryNotFound` if the parent directory doesn't exist
    ///
    /// # Note
    /// This does NOT create parent directories automatically. The parent must
    /// already exist.
    ///
    /// # Examples
    /// ```ignore
    /// let new_dir_id = vault_ops.create_directory_by_path("documents/archives")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn create_directory_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<DirId, VaultWriteError> {
        let (parent_dir_id, dirname) = self.resolve_parent_path(path.as_ref())?;
        debug!(parent_dir_id = %parent_dir_id, dirname = %dirname, "Resolved path for directory creation");
        self.create_directory(&parent_dir_id, &dirname)
    }

    /// Create a directory and all parent directories (like `mkdir -p`).
    ///
    /// This will create any missing intermediate directories along the path.
    /// If the directory already exists, this is a no-op.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/projects/new_project"
    ///
    /// # Returns
    /// The directory ID of the final (deepest) directory.
    ///
    /// # Examples
    /// ```ignore
    /// // Creates "a", "a/b", and "a/b/c" if they don't exist
    /// let dir_id = vault_ops.create_directory_all("a/b/c")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn create_directory_all(
        &self,
        path: impl AsRef<str>,
    ) -> Result<DirId, VaultWriteError> {
        let vault_path = VaultPath::new(path.as_ref());

        if vault_path.is_root() {
            return Ok(DirId::root());
        }

        let mut current_dir_id = DirId::root();

        for component in vault_path.components() {
            // Check if this directory already exists
            let dirs = self.list_directories(&current_dir_id)?;
            if let Some(existing) = dirs.into_iter().find(|d| d.name == component) {
                current_dir_id = existing.directory_id;
                trace!(component = %component, dir_id = %current_dir_id.as_str(), "Directory already exists");
            } else {
                // Create the directory
                current_dir_id = self.create_directory(&current_dir_id, component)?;
                debug!(component = %component, dir_id = %current_dir_id.as_str(), "Created directory");
            }
        }

        Ok(current_dir_id)
    }

    /// Create an empty file if it doesn't exist (like `touch`).
    ///
    /// If the file already exists, this is a no-op.
    /// Parent directories must already exist.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/newfile.txt"
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.touch("docs/newfile.txt")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn touch(&self, path: impl AsRef<str>) -> Result<(), VaultWriteError> {
        let vault_path = VaultPath::new(path.as_ref());

        // Check if file already exists
        if let Some(entry_type) = self.entry_type(path.as_ref()) {
            if entry_type.is_file() {
                trace!("File already exists, nothing to do");
                return Ok(());
            } else {
                return Err(VaultWriteError::PathExists {
                    path: vault_path.to_string(),
                });
            }
        }

        // Create empty file
        let (parent_dir_id, filename) = self.resolve_parent_path(path.as_ref())?;
        self.write_file(&parent_dir_id, &filename, &[])?;
        debug!("Created empty file");
        Ok(())
    }

    /// Append content to a file.
    ///
    /// If the file doesn't exist, it will be created with the given content.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/log.txt"
    /// * `content` - Bytes to append to the file
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.append("logs/app.log", b"New log entry\n")?;
    /// ```
    #[instrument(level = "debug", skip(self, content), fields(path = path.as_ref(), content_len = content.len()))]
    pub fn append(&self, path: impl AsRef<str>, content: &[u8]) -> Result<(), VaultWriteError> {
        let (parent_dir_id, filename) = self.resolve_parent_path(path.as_ref())?;

        // Try to read existing content
        let existing_content = match self.read_file(&parent_dir_id, &filename) {
            Ok(decrypted) => decrypted.content,
            Err(VaultOperationError::FileNotFound { .. }) => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        // Combine and write
        let mut new_content = existing_content;
        new_content.extend_from_slice(content);

        self.write_file(&parent_dir_id, &filename, &new_content)?;
        debug!(new_size = new_content.len(), "Appended content to file");
        Ok(())
    }

    /// Delete a directory by its path.
    ///
    /// The directory must be empty. Use `delete_directory_recursive_by_path()`
    /// to delete a directory with contents.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/old_folder"
    ///
    /// # Errors
    /// - `DirectoryNotEmpty` if the directory contains files or subdirectories
    /// - `DirectoryNotFound` if the directory doesn't exist
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.delete_directory_by_path("documents/empty_folder")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn delete_directory_by_path(&self, path: impl AsRef<str>) -> Result<(), VaultWriteError> {
        let (parent_dir_id, dirname) = self.resolve_parent_path(path.as_ref())?;
        debug!(parent_dir_id = %parent_dir_id, dirname = %dirname, "Resolved path for directory deletion");
        self.delete_directory(&parent_dir_id, &dirname)
    }

    /// Delete a directory and all its contents recursively by path.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/old_folder"
    ///
    /// # Returns
    /// Statistics about how many files and directories were deleted
    ///
    /// # Examples
    /// ```ignore
    /// let stats = vault_ops.delete_directory_recursive_by_path("documents/old_project")?;
    /// println!("Deleted {} files and {} directories", stats.files_deleted, stats.directories_deleted);
    /// ```
    #[instrument(level = "info", skip(self), fields(path = path.as_ref()))]
    pub fn delete_directory_recursive_by_path(
        &self,
        path: impl AsRef<str>,
    ) -> Result<DeleteStats, VaultWriteError> {
        let (parent_dir_id, dirname) = self.resolve_parent_path(path.as_ref())?;
        info!(parent_dir_id = %parent_dir_id, dirname = %dirname, "Resolved path for recursive directory deletion");
        self.delete_directory_recursive(&parent_dir_id, &dirname)
    }

    /// Rename a file by its path.
    ///
    /// The new name must be in the same directory (just the filename changes).
    ///
    /// # Arguments
    /// * `path` - The current path like "docs/old_name.txt"
    /// * `new_name` - The new filename (not a full path), e.g., "new_name.txt"
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.rename_file_by_path("documents/draft.txt", "final.txt")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref(), new_name = new_name))]
    pub fn rename_file_by_path(
        &self,
        path: impl AsRef<str>,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        let (dir_id, old_name) = self.resolve_parent_path(path.as_ref())?;
        debug!(dir_id = %dir_id, old_name = %old_name, "Resolved path for file rename");
        self.rename_file(&dir_id, &old_name, new_name)
    }

    /// Move a file from one path to another.
    ///
    /// # Arguments
    /// * `src_path` - Source path like "docs/file.txt"
    /// * `dest_path` - Destination path like "archive/file.txt"
    ///
    /// # Note
    /// The destination filename can be different from the source, allowing
    /// move-and-rename in a single operation.
    ///
    /// # Examples
    /// ```ignore
    /// // Move to a different directory
    /// vault_ops.move_file_by_path("inbox/report.txt", "archive/2024/report.txt")?;
    ///
    /// // Move and rename
    /// vault_ops.move_file_by_path("temp/draft.txt", "documents/final.txt")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(src_path = src_path.as_ref(), dest_path = dest_path.as_ref()))]
    pub fn move_file_by_path(
        &self,
        src_path: impl AsRef<str>,
        dest_path: impl AsRef<str>,
    ) -> Result<(), VaultWriteError> {
        let (src_dir_id, src_name) = self.resolve_parent_path(src_path.as_ref())?;
        let (dest_dir_id, dest_name) = self.resolve_parent_path(dest_path.as_ref())?;

        debug!(
            src_dir_id = %src_dir_id, src_name = %src_name,
            dest_dir_id = %dest_dir_id, dest_name = %dest_name,
            "Resolved paths for file move"
        );

        if src_dir_id == dest_dir_id && src_name == dest_name {
            return Err(VaultWriteError::SameSourceAndDestination {
                context: VaultOpContext::new()
                    .with_dir_id(src_dir_id.as_str())
                    .with_filename(&src_name),
            });
        }

        if src_dir_id == dest_dir_id {
            // Same directory, just rename
            self.rename_file(&src_dir_id, &src_name, &dest_name)
        } else if src_name == dest_name {
            // Different directory, same name
            self.move_file(&src_dir_id, &src_name, &dest_dir_id)
        } else {
            // Different directory and different name
            self.move_and_rename_file(&src_dir_id, &src_name, &dest_dir_id, &dest_name)
        }
    }

    /// Rename a directory by its path.
    ///
    /// The new name must be in the same parent directory (just the directory name changes).
    ///
    /// # Arguments
    /// * `path` - The current path like "docs/projects"
    /// * `new_name` - The new directory name (not a full path), e.g., "archived_projects"
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.rename_directory_by_path("documents/old_folder", "new_folder")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref(), new_name = new_name))]
    pub fn rename_directory_by_path(
        &self,
        path: impl AsRef<str>,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        let (parent_dir_id, old_name) = self.resolve_parent_path(path.as_ref())?;
        debug!(parent_dir_id = %parent_dir_id, old_name = %old_name, "Resolved path for directory rename");
        self.rename_directory(&parent_dir_id, &old_name, new_name)
    }

    /// Read a symlink target by its path.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/link_to_readme"
    ///
    /// # Returns
    /// The target path that the symlink points to.
    ///
    /// # Examples
    /// ```ignore
    /// let target = vault_ops.read_symlink_by_path("links/readme_link")?;
    /// println!("Symlink points to: {}", target);
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn read_symlink_by_path(&self, path: impl AsRef<str>) -> Result<String, VaultOperationError> {
        let (dir_id, name) = self.resolve_parent_path(path.as_ref())?;
        debug!(dir_id = %dir_id, name = %name, "Resolved path for symlink read");
        self.read_symlink(&dir_id, &name)
    }

    /// Create a symlink by its path.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/link_to_readme"
    /// * `target` - The target path the symlink should point to
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.create_symlink_by_path("links/readme_link", "../README.md")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref(), target = target))]
    pub fn create_symlink_by_path(
        &self,
        path: impl AsRef<str>,
        target: &str,
    ) -> Result<(), VaultWriteError> {
        let (dir_id, name) = self.resolve_parent_path(path.as_ref())?;
        debug!(dir_id = %dir_id, name = %name, "Resolved path for symlink creation");
        self.create_symlink(&dir_id, &name, target)
    }

    /// Delete a symlink by its path.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/link_to_readme"
    ///
    /// # Examples
    /// ```ignore
    /// vault_ops.delete_symlink_by_path("links/old_link")?;
    /// ```
    #[instrument(level = "debug", skip(self), fields(path = path.as_ref()))]
    pub fn delete_symlink_by_path(&self, path: impl AsRef<str>) -> Result<(), VaultWriteError> {
        let (dir_id, name) = self.resolve_parent_path(path.as_ref())?;
        debug!(dir_id = %dir_id, name = %name, "Resolved path for symlink deletion");
        self.delete_symlink(&dir_id, &name)
    }

    /// Get entry information by path.
    ///
    /// Returns a `DirEntry` containing full metadata for the file, directory,
    /// or symlink at the given path.
    ///
    /// # Arguments
    /// * `path` - A relative path like "docs/readme.txt" or "docs"
    ///
    /// # Returns
    /// - `Some(DirEntry)` if an entry exists at the path
    /// - `None` if nothing exists at the path
    ///
    /// # Examples
    /// ```ignore
    /// if let Some(entry) = vault_ops.get_entry("documents/report.txt") {
    ///     match entry {
    ///         DirEntry::File(info) => println!("File size: {}", info.encrypted_size),
    ///         DirEntry::Directory(info) => println!("Dir ID: {}", info.directory_id),
    ///         DirEntry::Symlink(info) => println!("Target: {}", info.target),
    ///     }
    /// }
    /// ```
    #[instrument(level = "trace", skip(self), fields(path = %path.as_ref()))]
    pub fn get_entry(&self, path: impl AsRef<str>) -> Option<DirEntry> {
        let vault_path = VaultPath::new(path.as_ref());

        if vault_path.is_root() {
            // Root directory - create a synthetic entry
            return Some(DirEntry::Directory(VaultDirectoryInfo {
                name: String::new(),
                directory_id: DirId::root(),
                encrypted_path: self.core.vault_path().join("d"),
                parent_directory_id: DirId::root(),
            }));
        }

        // Get the parent directory and the entry name
        let (parent_path, entry_name) = vault_path.split()?;

        // Resolve the parent directory
        let parent_dir_id = if parent_path.is_root() {
            DirId::root()
        } else {
            match self.resolve_path(parent_path.as_str()) {
                Ok((dir_id, true)) => dir_id,
                _ => return None, // Parent doesn't exist or isn't a directory
            }
        };

        // Check for symlink first
        if let Ok(symlinks) = self.list_symlinks(&parent_dir_id)
            && let Some(symlink) = symlinks.into_iter().find(|s| s.name == entry_name) {
                return Some(DirEntry::Symlink(symlink));
            }

        // Check for directory
        if let Ok(dirs) = self.list_directories(&parent_dir_id)
            && let Some(dir) = dirs.into_iter().find(|d| d.name == entry_name) {
                return Some(DirEntry::Directory(dir));
            }

        // Check for file
        if let Ok(files) = self.list_files(&parent_dir_id)
            && let Some(file) = files.into_iter().find(|f| f.name == entry_name) {
                return Some(DirEntry::File(file));
            }

        None
    }

    // Helper methods

    fn read_directory_info(
        &self,
        dir_path: &Path,
        encrypted_name: &str,
        parent_dir_id: &DirId,
    ) -> Result<VaultDirectoryInfo, VaultOperationError> {
        let dir_id_file = dir_path.join("dir.c9r");
        let dir_id_str = fs::read_to_string(&dir_id_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure {
                reason: format!("Failed to read directory ID: {e}"),
                context: VaultOpContext::new()
                    .with_encrypted_path(dir_path)
                    .with_dir_id(parent_dir_id.as_str()),
            })?
            .trim()
            .to_string();

        let decrypted_name = decrypt_filename(encrypted_name, parent_dir_id.as_str(), &self.master_key)?;

        Ok(VaultDirectoryInfo {
            name: decrypted_name,
            directory_id: DirId::from_raw(dir_id_str),
            encrypted_path: dir_path.to_path_buf(),
            parent_directory_id: parent_dir_id.clone(),
        })
    }
    
    fn read_shortened_directory_info(
        &self,
        dir_path: &Path,
        parent_dir_id: &DirId,
    ) -> Result<VaultDirectoryInfo, VaultOperationError> {
        let name_file = dir_path.join("name.c9s");
        let original_name = fs::read_to_string(&name_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure {
                reason: format!("Failed to read shortened name: {e}"),
                context: VaultOpContext::new()
                    .with_encrypted_path(dir_path)
                    .with_dir_id(parent_dir_id.as_str()),
            })?
            .trim()
            .to_string();

        let dir_id_file = dir_path.join("dir.c9r");
        let dir_id_str = fs::read_to_string(&dir_id_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure {
                reason: format!("Failed to read directory ID: {e}"),
                context: VaultOpContext::new()
                    .with_encrypted_path(dir_path)
                    .with_dir_id(parent_dir_id.as_str()),
            })?
            .trim()
            .to_string();

        let decrypted_name = decrypt_filename(&original_name, parent_dir_id.as_str(), &self.master_key)?;

        Ok(VaultDirectoryInfo {
            name: decrypted_name,
            directory_id: DirId::from_raw(dir_id_str),
            encrypted_path: dir_path.to_path_buf(),
            parent_directory_id: parent_dir_id.clone(),
        })
    }
    
    fn read_shortened_file_info(
        &self,
        dir_path: &Path,
        parent_dir_id: &DirId,
    ) -> Result<VaultFileInfo, VaultOperationError> {
        let name_file = dir_path.join("name.c9s");
        let original_name = fs::read_to_string(&name_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure {
                reason: format!("Failed to read shortened name: {e}"),
                context: VaultOpContext::new()
                    .with_encrypted_path(dir_path)
                    .with_dir_id(parent_dir_id.as_str()),
            })?
            .trim()
            .to_string();

        let decrypted_name = decrypt_filename(&original_name, parent_dir_id.as_str(), &self.master_key)?;

        let contents_file = dir_path.join("contents.c9r");
        let metadata = fs::metadata(&contents_file)?;

        Ok(VaultFileInfo {
            name: decrypted_name,
            encrypted_name: dir_path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            encrypted_path: contents_file,
            encrypted_size: metadata.len(),
            is_shortened: true,
        })
    }

    fn read_symlink_info(
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
        let encrypted_data = fs::read(&symlink_file).map_err(|_| {
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

    fn read_shortened_symlink_info(
        &self,
        symlink_path: &Path,
        parent_dir_id: &DirId,
    ) -> Result<VaultSymlinkInfo, VaultOperationError> {
        // Read the original encrypted name from name.c9s
        let name_file = symlink_path.join("name.c9s");
        let original_name = fs::read_to_string(&name_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure {
                reason: format!("Failed to read shortened name: {e}"),
                context: VaultOpContext::new()
                    .with_encrypted_path(symlink_path)
                    .with_dir_id(parent_dir_id.as_str()),
            })?
            .trim()
            .to_string();

        self.read_symlink_info(symlink_path, &original_name, parent_dir_id, true)
    }

    // ==================== Write Operations ====================

    /// Write a file to the vault
    ///
    /// # Arguments
    /// * `dir_id` - Directory ID where the file should be created
    /// * `filename` - The cleartext filename
    /// * `content` - The file contents
    ///
    /// # Returns
    /// The encrypted path where the file was written
    #[instrument(level = "info", skip(self, content), fields(dir_id = %dir_id.as_str(), filename = %filename, content_size = content.len()))]
    pub fn write_file(
        &self,
        dir_id: &DirId,
        filename: &str,
        content: &[u8],
    ) -> Result<PathBuf, VaultWriteError> {
        info!("Writing file to vault");

        // 1. Calculate storage path for this directory
        let storage_path = self.calculate_directory_storage_path(dir_id)?;
        trace!(storage_path = %storage_path.display(), "Calculated storage path");

        // 2. Ensure storage directory exists
        fs::create_dir_all(&storage_path)?;

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
            self.write_shortened_file(&storage_path, &encrypted_name, &file_data)?
        } else {
            let path = storage_path.join(format!("{encrypted_name}.c9r"));
            self.atomic_write(&path, &file_data)?;
            path
        };

        info!(encrypted_path = %file_path.display(), "File written successfully");
        Ok(file_path)
    }

    /// Create a new directory in the vault
    ///
    /// # Arguments
    /// * `parent_dir_id` - Directory ID of the parent
    /// * `name` - The cleartext directory name
    ///
    /// # Returns
    /// The newly generated directory ID
    #[instrument(level = "info", skip(self), fields(parent_dir_id = %parent_dir_id.as_str(), name = %name))]
    pub fn create_directory(
        &self,
        parent_dir_id: &DirId,
        name: &str,
    ) -> Result<DirId, VaultWriteError> {
        info!("Creating new directory in vault");

        // 1. Calculate storage path for parent directory
        let parent_storage_path = self.calculate_directory_storage_path(parent_dir_id)?;
        trace!(parent_storage_path = %parent_storage_path.display(), "Calculated parent storage path");
        fs::create_dir_all(&parent_storage_path)?;

        // 2. Generate a new directory ID (UUID)
        let dir_id_str = uuid::Uuid::new_v4().to_string();
        let dir_id = DirId::from_raw(&dir_id_str);
        debug!(new_dir_id = %dir_id_str, "Generated new directory ID");

        // 3. Encrypt the directory name
        let encrypted_name = encrypt_filename(name, parent_dir_id.as_str(), &self.master_key)?;

        // 4. Create the encrypted directory structure
        if encrypted_name.len() > self.core.shortening_threshold() {
            self.create_shortened_directory(
                &parent_storage_path,
                &encrypted_name,
                &dir_id,
            )?;
        } else {
            let encrypted_dir_path = parent_storage_path.join(format!("{encrypted_name}.c9r"));
            fs::create_dir_all(&encrypted_dir_path)?;
            self.atomic_write(&encrypted_dir_path.join("dir.c9r"), dir_id.as_str().as_bytes())?;
        }

        // 5. Create the storage directory for this new directory
        let new_storage_path = self.calculate_directory_storage_path(&dir_id)?;
        fs::create_dir_all(&new_storage_path)?;

        // 6. Write dirid.c9r backup file in the content directory
        // This stores the directory's OWN ID (not the parent's) using the vault's cipher combo.
        // The file is placed in the content directory (new_storage_path), not the .c9r folder.
        // Reference: Java DirectoryIdBackup.write() stores ciphertextDir.dirId() in ciphertextDir.path()
        let encrypted_dir_id = self.core.cipher_combo().encrypt_dir_id_backup(dir_id.as_str(), &self.master_key)?;
        self.atomic_write(&new_storage_path.join("dirid.c9r"), &encrypted_dir_id)?;

        info!(created_dir_id = %dir_id.as_str(), "Directory created successfully");
        Ok(dir_id)
    }

    /// Delete a file from the vault
    ///
    /// # Arguments
    /// * `dir_id` - Directory ID containing the file
    /// * `filename` - The cleartext filename to delete
    #[instrument(level = "info", skip(self), fields(dir_id = %dir_id.as_str(), filename = %filename))]
    pub fn delete_file(&self, dir_id: &DirId, filename: &str) -> Result<(), VaultWriteError> {
        info!("Deleting file from vault");

        // 1. Find the file using list_files
        debug!("Looking up file to delete");
        let ctx = VaultOpContext::new()
            .with_filename(filename)
            .with_dir_id(dir_id.as_str());
        let files = self.list_files(dir_id).map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            _ => VaultWriteError::Io {
                source: std::io::Error::other(e.to_string()),
                context: ctx.clone(),
            },
        })?;

        let file_info = files
            .into_iter()
            .find(|f| f.name == filename)
            .ok_or_else(|| {
                warn!("File not found for deletion");
                VaultWriteError::FileNotFound {
                    filename: filename.to_string(),
                    context: ctx.clone(),
                }
            })?;

        // 2. Handle shortened vs regular files
        debug!(is_shortened = file_info.is_shortened, encrypted_path = %file_info.encrypted_path.display(), "Removing encrypted file");
        if file_info.is_shortened {
            // Remove the entire .c9s directory
            let parent = file_info
                .encrypted_path
                .parent()
                .ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                    reason: "No parent directory".to_string(),
                    context: ctx.clone().with_encrypted_path(&file_info.encrypted_path),
                })?;
            fs::remove_dir_all(parent)?;
        } else {
            // Remove the .c9r file
            fs::remove_file(&file_info.encrypted_path)?;
        }

        info!("File deleted successfully");
        Ok(())
    }

    /// Delete a directory from the vault (must be empty)
    ///
    /// # Arguments
    /// * `parent_dir_id` - Directory ID of the parent containing the directory
    /// * `dir_name` - The cleartext name of the directory to delete
    #[instrument(level = "info", skip(self), fields(parent_dir_id = %parent_dir_id.as_str(), dir_name = %dir_name))]
    pub fn delete_directory(
        &self,
        parent_dir_id: &DirId,
        dir_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Deleting directory from vault");

        let ctx = VaultOpContext::new()
            .with_filename(dir_name)
            .with_dir_id(parent_dir_id.as_str());

        // 1. Find the directory to get its ID
        debug!("Looking up directory to delete");
        let dirs = self.list_directories(parent_dir_id).map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            _ => VaultWriteError::Io {
                source: std::io::Error::other(e.to_string()),
                context: ctx.clone(),
            },
        })?;

        let dir_info = dirs
            .into_iter()
            .find(|d| d.name == dir_name)
            .ok_or_else(|| {
                warn!("Directory not found for deletion");
                VaultWriteError::DirectoryNotFound {
                    name: dir_name.to_string(),
                    context: ctx.clone(),
                }
            })?;

        trace!(target_dir_id = %dir_info.directory_id.as_str(), "Found directory to delete");

        // 2. Check directory is empty
        debug!("Checking if directory is empty");
        let target_ctx = ctx.clone().with_dir_id(dir_info.directory_id.as_str());
        let files = self.list_files(&dir_info.directory_id).map_err(|e| match e {
            VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
            _ => VaultWriteError::Io {
                source: std::io::Error::other(e.to_string()),
                context: target_ctx.clone(),
            },
        })?;
        let subdirs = self
            .list_directories(&dir_info.directory_id)
            .map_err(|e| match e {
                VaultOperationError::Io { source, context } => VaultWriteError::Io { source, context },
                _ => VaultWriteError::Io {
                    source: std::io::Error::other(e.to_string()),
                    context: target_ctx.clone(),
                },
            })?;

        if !files.is_empty() || !subdirs.is_empty() {
            warn!(file_count = files.len(), subdir_count = subdirs.len(), "Cannot delete non-empty directory");
            return Err(VaultWriteError::DirectoryNotEmpty {
                context: target_ctx.with_encrypted_path(&dir_info.encrypted_path),
            });
        }

        // 3. Remove the storage directory for this dir_id
        debug!("Removing storage directory");
        let storage_path = self.calculate_directory_storage_path(&dir_info.directory_id)?;
        if storage_path.exists() {
            fs::remove_dir_all(&storage_path)?;
        }

        // 4. Remove the directory entry from parent
        debug!("Removing directory entry from parent");
        if dir_info.encrypted_path.exists() {
            fs::remove_dir_all(&dir_info.encrypted_path)?;
        }

        info!("Directory deleted successfully");
        Ok(())
    }

    /// Rename a file within the same directory
    ///
    /// This handles all filename length transitions (short↔long) correctly.
    /// The operation is atomic: the new file is created before the old one is removed.
    ///
    /// # Arguments
    /// * `dir_id` - Directory ID containing the file
    /// * `old_name` - Current cleartext filename
    /// * `new_name` - New cleartext filename
    ///
    /// # Errors
    /// - `FileNotFound` if the source file doesn't exist
    /// - `FileAlreadyExists` if a file with the new name already exists
    /// - `SameSourceAndDestination` if old_name equals new_name
    #[instrument(level = "info", skip(self), fields(dir_id = %dir_id.as_str(), old_name = %old_name, new_name = %new_name))]
    pub fn rename_file(
        &self,
        dir_id: &DirId,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        info!("Renaming file in vault");

        let ctx = VaultOpContext::new()
            .with_filename(old_name)
            .with_dir_id(dir_id.as_str());

        // Fast path: no-op if names are identical
        if old_name == new_name {
            debug!("Source and destination names are identical");
            return Err(VaultWriteError::SameSourceAndDestination {
                context: ctx,
            });
        }

        // Find the source file
        let files = self.list_files(dir_id)?;
        let source_info = files
            .iter()
            .find(|f| f.name == old_name)
            .ok_or_else(|| VaultWriteError::FileNotFound {
                filename: old_name.to_string(),
                context: ctx.clone(),
            })?;

        // Check that target doesn't exist
        if files.iter().any(|f| f.name == new_name) {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: new_name.to_string(),
                context: ctx.clone().with_filename(new_name),
            });
        }

        let storage_path = self.calculate_directory_storage_path(dir_id)?;

        // Encrypt the new filename
        let new_encrypted_name = encrypt_filename(new_name, dir_id.as_str(), &self.master_key)?;
        let new_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Read the raw encrypted file data (no decryption needed - just copy bytes)
        let file_data = fs::read(&source_info.encrypted_path)?;

        // Write to new location first (crash-safe: create before delete)
        if new_is_long {
            self.write_shortened_file(&storage_path, &new_encrypted_name, &file_data)?;
        } else {
            let new_path = storage_path.join(format!("{new_encrypted_name}.c9r"));
            self.atomic_write(&new_path, &file_data)?;
        }

        // Remove the old file
        if source_info.is_shortened {
            // Remove entire .c9s directory
            let parent = source_info
                .encrypted_path
                .parent()
                .ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                    reason: "No parent directory".to_string(),
                    context: ctx.clone().with_encrypted_path(&source_info.encrypted_path),
                })?;
            fs::remove_dir_all(parent)?;
        } else {
            fs::remove_file(&source_info.encrypted_path)?;
        }

        Ok(())
    }

    /// Rename a directory within its parent
    ///
    /// This only changes the directory's name in the parent; the directory's
    /// internal ID remains the same, so all children remain valid.
    ///
    /// # Arguments
    /// * `parent_dir_id` - Directory ID of the parent containing the directory
    /// * `old_name` - Current cleartext directory name
    /// * `new_name` - New cleartext directory name
    ///
    /// # Errors
    /// - `DirectoryNotFound` if the source directory doesn't exist
    /// - `DirectoryAlreadyExists` if a directory with the new name already exists
    /// - `SameSourceAndDestination` if old_name equals new_name
    pub fn rename_directory(
        &self,
        parent_dir_id: &DirId,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        let ctx = VaultOpContext::new()
            .with_filename(old_name)
            .with_dir_id(parent_dir_id.as_str());

        // Fast path: no-op if names are identical
        if old_name == new_name {
            return Err(VaultWriteError::SameSourceAndDestination {
                context: ctx,
            });
        }

        // Find the source directory
        let dirs = self.list_directories(parent_dir_id)?;
        let source_info = dirs
            .iter()
            .find(|d| d.name == old_name)
            .ok_or_else(|| VaultWriteError::DirectoryNotFound {
                name: old_name.to_string(),
                context: ctx.clone(),
            })?;

        // Check that target doesn't exist
        if dirs.iter().any(|d| d.name == new_name) {
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
            self.create_shortened_directory(
                &parent_storage_path,
                &new_encrypted_name,
                dir_id,
            )?;
        } else {
            let new_path = parent_storage_path.join(format!("{new_encrypted_name}.c9r"));
            fs::create_dir_all(&new_path)?;
            self.atomic_write(&new_path.join("dir.c9r"), dir_id.as_str().as_bytes())?;

            // Note: dirid.c9r is in the content directory, not the .c9r folder.
            // Since the content directory doesn't change during a rename, we don't need
            // to update dirid.c9r here. It should already exist from directory creation.
        }

        // Remove the old directory entry (not the storage directory - that stays!)
        fs::remove_dir_all(&source_info.encrypted_path)?;

        Ok(())
    }

    /// Delete a directory and all its contents recursively
    ///
    /// This performs a depth-first traversal, deleting all files and subdirectories
    /// before removing the directory itself.
    ///
    /// # Arguments
    /// * `parent_dir_id` - Directory ID of the parent containing the directory
    /// * `dir_name` - The cleartext name of the directory to delete
    ///
    /// # Returns
    /// Statistics about how many files and directories were deleted
    ///
    /// # Errors
    /// Fails fast on the first error encountered. Partial deletions may occur.
    pub fn delete_directory_recursive(
        &self,
        parent_dir_id: &DirId,
        dir_name: &str,
    ) -> Result<DeleteStats, VaultWriteError> {
        let ctx = VaultOpContext::new()
            .with_filename(dir_name)
            .with_dir_id(parent_dir_id.as_str());

        // Find the directory to get its ID
        let dirs = self.list_directories(parent_dir_id)?;
        let dir_info = dirs
            .into_iter()
            .find(|d| d.name == dir_name)
            .ok_or_else(|| VaultWriteError::DirectoryNotFound {
                name: dir_name.to_string(),
                context: ctx,
            })?;

        // Recursively delete contents
        let mut stats = self.delete_directory_contents_recursive(&dir_info.directory_id)?;

        // Now the directory is empty, delete it using the normal method
        // But we already have the info, so do it directly:

        // Remove the storage directory
        let storage_path = self.calculate_directory_storage_path(&dir_info.directory_id)?;
        if storage_path.exists() {
            fs::remove_dir_all(&storage_path)?;
        }

        // Remove the directory entry from parent
        if dir_info.encrypted_path.exists() {
            fs::remove_dir_all(&dir_info.encrypted_path)?;
        }

        stats.directories_deleted += 1;
        Ok(stats)
    }

    /// Move a file from one directory to another
    ///
    /// This operation requires re-encrypting the filename (since it uses the
    /// directory ID as associated data), but the file content is copied directly
    /// without decryption for efficiency.
    ///
    /// # Arguments
    /// * `src_dir_id` - Source directory ID
    /// * `filename` - Cleartext filename
    /// * `dest_dir_id` - Destination directory ID
    ///
    /// # Errors
    /// - `FileNotFound` if the source file doesn't exist
    /// - `FileAlreadyExists` if a file with the same name exists in destination
    /// - `SameSourceAndDestination` if source and destination directories are the same
    ///
    /// # Note
    /// This is NOT atomic across directories. If the operation fails after creating
    /// the destination file but before deleting the source, both files will exist.
    /// Consider using a journal or WAL for crash-safe moves in production.
    pub fn move_file(
        &self,
        src_dir_id: &DirId,
        filename: &str,
        dest_dir_id: &DirId,
    ) -> Result<(), VaultWriteError> {
        let src_ctx = VaultOpContext::new()
            .with_filename(filename)
            .with_dir_id(src_dir_id.as_str());

        // Same directory move is just a no-op (use rename_file for same-dir rename)
        if src_dir_id == dest_dir_id {
            return Err(VaultWriteError::SameSourceAndDestination {
                context: src_ctx,
            });
        }

        // Find the source file
        let src_files = self.list_files(src_dir_id)?;
        let source_info = src_files
            .iter()
            .find(|f| f.name == filename)
            .ok_or_else(|| VaultWriteError::FileNotFound {
                filename: filename.to_string(),
                context: src_ctx.clone(),
            })?;

        // Check that target doesn't exist
        let dest_files = self.list_files(dest_dir_id)?;
        if dest_files.iter().any(|f| f.name == filename) {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: filename.to_string(),
                context: VaultOpContext::new()
                    .with_filename(filename)
                    .with_dir_id(dest_dir_id.as_str()),
            });
        }

        // Ensure destination directory exists
        let dest_storage_path = self.calculate_directory_storage_path(dest_dir_id)?;
        fs::create_dir_all(&dest_storage_path)?;

        // Read the raw encrypted file data (header + encrypted content)
        // No decryption needed - file content encryption doesn't use dir_id
        let file_data = fs::read(&source_info.encrypted_path)?;

        // Encrypt the filename with the NEW directory ID
        let new_encrypted_name = encrypt_filename(filename, dest_dir_id.as_str(), &self.master_key)?;
        let dest_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Write to destination (create before delete for crash safety)
        if dest_is_long {
            self.write_shortened_file(&dest_storage_path, &new_encrypted_name, &file_data)?;
        } else {
            let dest_path = dest_storage_path.join(format!("{new_encrypted_name}.c9r"));
            self.atomic_write(&dest_path, &file_data)?;
        }

        // Remove from source
        if source_info.is_shortened {
            let parent = source_info
                .encrypted_path
                .parent()
                .ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                    reason: "No parent directory".to_string(),
                    context: src_ctx.clone().with_encrypted_path(&source_info.encrypted_path),
                })?;
            fs::remove_dir_all(parent)?;
        } else {
            fs::remove_file(&source_info.encrypted_path)?;
        }

        Ok(())
    }

    /// Move a file and optionally rename it in one operation
    ///
    /// This is more efficient than move + rename when both are needed.
    ///
    /// # Arguments
    /// * `src_dir_id` - Source directory ID
    /// * `old_name` - Current cleartext filename
    /// * `dest_dir_id` - Destination directory ID
    /// * `new_name` - New cleartext filename in destination
    pub fn move_and_rename_file(
        &self,
        src_dir_id: &DirId,
        old_name: &str,
        dest_dir_id: &DirId,
        new_name: &str,
    ) -> Result<(), VaultWriteError> {
        // Check for no-op
        if src_dir_id == dest_dir_id && old_name == new_name {
            return Err(VaultWriteError::SameSourceAndDestination {
                context: VaultOpContext::new()
                    .with_dir_id(src_dir_id.as_str())
                    .with_filename(old_name),
            });
        }

        // Same directory? Use rename instead
        if src_dir_id == dest_dir_id {
            return self.rename_file(src_dir_id, old_name, new_name);
        }

        // Find the source file
        let src_files = self.list_files(src_dir_id)?;
        let source_info = src_files
            .iter()
            .find(|f| f.name == old_name)
            .ok_or_else(|| VaultWriteError::FileNotFound {
                filename: old_name.to_string(),
                context: VaultOpContext::new().with_dir_id(src_dir_id.as_str()),
            })?;

        // Check that target doesn't exist (with new name)
        let dest_files = self.list_files(dest_dir_id)?;
        if dest_files.iter().any(|f| f.name == new_name) {
            return Err(VaultWriteError::FileAlreadyExists {
                filename: new_name.to_string(),
                context: VaultOpContext::new().with_dir_id(dest_dir_id.as_str()),
            });
        }

        // Ensure destination directory exists
        let dest_storage_path = self.calculate_directory_storage_path(dest_dir_id)?;
        fs::create_dir_all(&dest_storage_path)?;

        // Read the raw encrypted file data
        let file_data = fs::read(&source_info.encrypted_path)?;

        // Encrypt the NEW filename with the NEW directory ID
        let new_encrypted_name = encrypt_filename(new_name, dest_dir_id.as_str(), &self.master_key)?;
        let dest_is_long = new_encrypted_name.len() > self.core.shortening_threshold();

        // Write to destination
        if dest_is_long {
            self.write_shortened_file(&dest_storage_path, &new_encrypted_name, &file_data)?;
        } else {
            let dest_path = dest_storage_path.join(format!("{new_encrypted_name}.c9r"));
            self.atomic_write(&dest_path, &file_data)?;
        }

        // Remove from source
        if source_info.is_shortened {
            let parent = source_info
                .encrypted_path
                .parent()
                .ok_or_else(|| VaultWriteError::AtomicWriteFailed {
                    reason: "No parent directory".to_string(),
                    context: VaultOpContext::new().with_vault_path(source_info.encrypted_path.display().to_string()),
                })?;
            fs::remove_dir_all(parent)?;
        } else {
            fs::remove_file(&source_info.encrypted_path)?;
        }

        Ok(())
    }

    // ==================== Write Helper Methods ====================

    /// Recursively delete all contents of a directory (but not the directory itself)
    fn delete_directory_contents_recursive(
        &self,
        dir_id: &DirId,
    ) -> Result<DeleteStats, VaultWriteError> {
        let mut stats = DeleteStats::default();

        // Delete all files first
        let files = self.list_files(dir_id)?;
        for file in files {
            self.delete_file(dir_id, &file.name)?;
            stats.files_deleted += 1;
        }

        // Recursively delete all subdirectories
        let subdirs = self.list_directories(dir_id)?;
        for subdir in subdirs {
            let sub_stats = self.delete_directory_recursive(dir_id, &subdir.name)?;
            stats.files_deleted += sub_stats.files_deleted;
            stats.directories_deleted += sub_stats.directories_deleted;
        }

        Ok(stats)
    }

    /// Write a file with a shortened name (.c9s format)
    fn write_shortened_file(
        &self,
        storage_path: &Path,
        encrypted_name: &str,
        file_data: &[u8],
    ) -> Result<PathBuf, VaultWriteError> {
        let hash = create_c9s_filename(encrypted_name);
        let short_dir = storage_path.join(format!("{hash}.c9s"));
        fs::create_dir_all(&short_dir)?;

        // Write name.c9s (contains the original encrypted name)
        self.atomic_write(&short_dir.join("name.c9s"), encrypted_name.as_bytes())?;

        // Write contents.c9r (contains the actual file data)
        let contents_path = short_dir.join("contents.c9r");
        self.atomic_write(&contents_path, file_data)?;

        Ok(contents_path)
    }

    /// Create a directory with a shortened name (.c9s format)
    ///
    /// Creates a `.c9s` directory structure containing:
    /// - `name.c9s`: The full encrypted name
    /// - `dir.c9r`: The directory ID (plaintext UUID)
    ///
    /// Note: This does NOT create `dirid.c9r` - that file belongs in the content
    /// directory (d/XX/...) and is handled by the caller.
    fn create_shortened_directory(
        &self,
        parent_storage_path: &Path,
        encrypted_name: &str,
        dir_id: &DirId,
    ) -> Result<PathBuf, VaultWriteError> {
        let hash = create_c9s_filename(encrypted_name);
        let short_dir = parent_storage_path.join(format!("{hash}.c9s"));
        fs::create_dir_all(&short_dir)?;

        // Write name.c9s (contains the original encrypted name)
        self.atomic_write(&short_dir.join("name.c9s"), encrypted_name.as_bytes())?;

        // Write dir.c9r (contains the directory ID)
        self.atomic_write(&short_dir.join("dir.c9r"), dir_id.as_str().as_bytes())?;

        // Note: dirid.c9r is NOT written here. It belongs in the content directory (d/XX/...),
        // not in the .c9s folder. The caller (create_directory) handles writing dirid.c9r
        // to the correct location with the directory's own ID using AES-GCM file encryption.

        Ok(short_dir)
    }

    /// Write data atomically using temp file + rename pattern
    fn atomic_write(&self, path: &Path, content: &[u8]) -> Result<(), VaultWriteError> {
        let parent = path.parent().ok_or_else(|| {
            VaultWriteError::AtomicWriteFailed {
                reason: "No parent directory".to_string(),
                context: VaultOpContext::new().with_vault_path(path.display().to_string()),
            }
        })?;

        // Create temp file in the same directory (ensures same filesystem for rename)
        let mut temp_file = tempfile::NamedTempFile::new_in(parent)?;
        temp_file.write_all(content)?;
        temp_file.persist(path).map_err(|e| {
            VaultWriteError::AtomicWriteFailed {
                reason: format!("Failed to persist temp file: {e}"),
                context: VaultOpContext::new().with_vault_path(path.display().to_string()),
            }
        })?;

        Ok(())
    }

    // ==================== Symlink Operations ====================

    /// Read a symlink's target by providing the directory ID and symlink name
    ///
    /// Symlinks are stored as `.c9r` directories containing a `symlink.c9r` file,
    /// which holds the encrypted target path using file content encryption (AES-GCM).
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), name = %name))]
    pub fn read_symlink(
        &self,
        directory_id: &DirId,
        name: &str,
    ) -> Result<String, VaultOperationError> {
        debug!("Looking up symlink in directory");

        // Calculate the directory storage path
        let dir_path = self.calculate_directory_storage_path(directory_id)?;

        // Encrypt the symlink name to find it on disk
        let encrypted_name = encrypt_filename(name, directory_id.as_str(), &self.master_key)?;
        let symlink_dir = dir_path.join(format!("{encrypted_name}.c9r"));

        if !symlink_dir.exists() {
            // Try shortened name (.c9s format)
            let shortened_hash = create_c9s_filename(&encrypted_name);
            let shortened_dir = dir_path.join(format!("{shortened_hash}.c9s"));

            if shortened_dir.exists() {
                let symlink_file = shortened_dir.join("symlink.c9r");
                if symlink_file.exists() {
                    let encrypted_data = fs::read(&symlink_file)?;
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
        if !symlink_file.exists() {
            return Err(VaultOperationError::NotASymlink {
                path: name.to_string(),
            });
        }

        let encrypted_data = fs::read(&symlink_file)?;
        let target = decrypt_symlink_target(&encrypted_data, &self.master_key)?;
        info!(target_len = target.len(), "Symlink target decrypted successfully");
        Ok(target)
    }

    /// Create a symlink in the vault
    ///
    /// Creates a `.c9r` directory containing a `symlink.c9r` file with the
    /// encrypted target path.
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), name = %name))]
    pub fn create_symlink(
        &self,
        directory_id: &DirId,
        name: &str,
        target: &str,
    ) -> Result<(), VaultWriteError> {
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

        // Ensure storage directory exists (like write_file does)
        fs::create_dir_all(&dir_path)?;

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
        if symlink_dir.exists() {
            return Err(VaultWriteError::SymlinkAlreadyExists {
                name: name.to_string(),
                context: VaultOpContext::new()
                    .with_filename(name)
                    .with_dir_id(directory_id.as_str()),
            });
        }

        // Create the symlink directory
        fs::create_dir_all(&symlink_dir)?;

        // If shortened, write the name.c9s file
        if is_shortened {
            fs::write(symlink_dir.join("name.c9s"), &encrypted_name)?;
        }

        // Encrypt and write the symlink target
        let encrypted_target = encrypt_symlink_target(target, &self.master_key)?;
        fs::write(symlink_dir.join("symlink.c9r"), &encrypted_target)?;

        info!("Symlink created successfully");
        Ok(())
    }

    /// Delete a symlink from the vault
    #[instrument(level = "debug", skip(self), fields(dir_id = %directory_id.as_str(), name = %name))]
    pub fn delete_symlink(
        &self,
        directory_id: &DirId,
        name: &str,
    ) -> Result<(), VaultWriteError> {
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

        if symlink_dir.exists() && symlink_dir.join("symlink.c9r").exists() {
            fs::remove_dir_all(&symlink_dir)?;
            info!("Symlink deleted successfully");
            return Ok(());
        }

        // Try shortened name
        let shortened_hash = create_c9s_filename(&encrypted_name);
        let shortened_dir = dir_path.join(format!("{shortened_hash}.c9s"));

        if shortened_dir.exists() && shortened_dir.join("symlink.c9r").exists() {
            fs::remove_dir_all(&shortened_dir)?;
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

    // ==================== Recovery Operations ====================

    /// Recover a directory's ID from its dirid.c9r backup file.
    ///
    /// The `dirid.c9r` file is stored in the content directory (`d/XX/.../dirid.c9r`)
    /// and contains the directory's OWN ID encrypted using AES-GCM file format.
    /// This can be used to recover a corrupted `dir.c9r` file.
    ///
    /// **Note**: Unlike what the Cryptomator documentation suggests, `dirid.c9r`
    /// stores the directory's own ID, NOT the parent's ID. This was verified by
    /// examining the Java reference implementation (`DirectoryIdBackup.java`).
    ///
    /// # Arguments
    ///
    /// * `content_dir_path` - Path to the content directory (d/XX/.../), NOT the .c9r folder
    ///
    /// # Returns
    ///
    /// The decrypted directory ID, or an error if recovery fails.
    ///
    /// # Errors
    ///
    /// - `VaultOperationError::Io`: If dirid.c9r cannot be read
    /// - `VaultOperationError::FileDecryption`: If decryption fails (integrity violation)
    pub fn recover_dir_id_from_backup(
        &self,
        content_dir_path: &Path,
    ) -> Result<DirId, VaultOperationError> {
        let dirid_file = content_dir_path.join("dirid.c9r");
        let encrypted_data = fs::read(&dirid_file)?;

        let dir_id_str = self.core.cipher_combo().decrypt_dir_id_backup(&encrypted_data, &self.master_key)?;

        Ok(DirId::from_raw(&dir_id_str))
    }

    /// Verify that a content directory matches a directory ID.
    ///
    /// Reads the `dirid.c9r` backup file and verifies that it contains the
    /// expected directory ID. Returns `true` if the IDs match.
    ///
    /// # Arguments
    ///
    /// * `content_dir_path` - Path to the content directory (d/XX/.../dirid.c9r)
    /// * `expected_dir_id` - The directory ID we expect to find
    ///
    /// # Returns
    ///
    /// `true` if the backup matches, `false` if it doesn't match or can't be read.
    pub fn verify_dir_id_backup(
        &self,
        content_dir_path: &Path,
        expected_dir_id: &DirId,
    ) -> bool {
        match self.recover_dir_id_from_backup(content_dir_path) {
            Ok(recovered_id) => recovered_id.as_str() == expected_dir_id.as_str(),
            Err(_) => false,
        }
    }

    /// Recover the parent directory ID from the dirid.c9r backup file.
    ///
    /// This reads the encrypted parent directory ID from the dirid.c9r file
    /// in the given directory path and decrypts it using the directory's own ID.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - Path to the encrypted directory (containing dirid.c9r)
    /// * `dir_id` - The directory's own ID (used for decryption)
    ///
    /// # Returns
    ///
    /// The decrypted parent directory ID.
    pub fn recover_parent_dir_id(
        &self,
        dir_path: &Path,
        dir_id: &DirId,
    ) -> Result<DirId, VaultOperationError> {
        let dirid_file = dir_path.join("dirid.c9r");
        let encrypted_data = fs::read(&dirid_file).map_err(|e| VaultOperationError::Io {
            source: e,
            context: VaultOpContext::new().with_vault_path(dir_path.to_string_lossy()),
        })?;
        let parent_id_str = decrypt_parent_dir_id(&encrypted_data, dir_id.as_str(), &self.master_key)?;
        Ok(DirId::from_raw(parent_id_str))
    }

    /// Recover the directory tree structure from dirid.c9r backup files.
    ///
    /// This function scans the vault's encrypted directory structure and attempts
    /// to reconstruct the parent-child relationships by reading dirid.c9r backup
    /// files. This is useful for vault recovery when dir.c9r files are corrupted.
    ///
    /// # Returns
    ///
    /// A vector of `RecoveredDirectoryInfo` structs containing the recovered
    /// parent-child relationships for all directories with valid dirid.c9r files.
    ///
    /// # Note
    ///
    /// Directories without dirid.c9r files or with corrupted backup files will
    /// be skipped with a warning printed to stderr. The root directory (empty ID)
    /// has no parent and won't appear in the results as a child.
    pub fn recover_directory_tree(&self) -> Result<Vec<RecoveredDirectoryInfo>, VaultOperationError> {
        let mut recovered = Vec::new();
        let d_dir = self.core.vault_path().join("d");

        if !d_dir.exists() {
            return Ok(recovered);
        }

        // Walk through all directories under /d/
        for prefix_entry in fs::read_dir(&d_dir)? {
            let prefix_entry = prefix_entry?;
            let prefix_path = prefix_entry.path();

            if !prefix_path.is_dir() {
                continue;
            }

            for hash_entry in fs::read_dir(&prefix_path)? {
                let hash_entry = hash_entry?;
                let storage_path = hash_entry.path();

                if !storage_path.is_dir() {
                    continue;
                }

                // Look for .c9r directories (regular directories) and .c9s directories (shortened)
                self.recover_from_storage_directory(&storage_path, &mut recovered)?;
            }
        }

        Ok(recovered)
    }

    /// Helper function to scan a storage directory for directories with dirid.c9r backups.
    fn recover_from_storage_directory(
        &self,
        storage_path: &Path,
        recovered: &mut Vec<RecoveredDirectoryInfo>,
    ) -> Result<(), VaultOperationError> {
        for entry in fs::read_dir(storage_path)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if !path.is_dir() {
                continue;
            }

            // Check for .c9r directories (regular encrypted directories)
            if file_name.ends_with(".c9r") {
                if let Some(info) = self.try_recover_directory(&path) {
                    recovered.push(info);
                }
            }
            // Check for .c9s directories (shortened names)
            else if file_name.ends_with(".c9s") {
                // Check if this is a directory (has dir.c9r) rather than a file
                if path.join("dir.c9r").exists()
                    && let Some(info) = self.try_recover_directory(&path)
                {
                    recovered.push(info);
                }
            }
        }

        Ok(())
    }

    /// Try to recover directory info from a .c9r or .c9s directory.
    fn try_recover_directory(&self, dir_path: &Path) -> Option<RecoveredDirectoryInfo> {
        // Read the directory ID from dir.c9r
        let dir_id_file = dir_path.join("dir.c9r");
        let dir_id_str = fs::read_to_string(&dir_id_file).ok()?.trim().to_string();
        let dir_id = DirId::from_raw(&dir_id_str);

        // Read and decrypt the parent ID from dirid.c9r
        let dirid_file = dir_path.join("dirid.c9r");
        let encrypted_parent_id = fs::read(&dirid_file).ok()?;

        match decrypt_parent_dir_id(&encrypted_parent_id, dir_id.as_str(), &self.master_key) {
            Ok(parent_dir_id_str) => Some(RecoveredDirectoryInfo {
                directory_id: dir_id,
                parent_directory_id: DirId::from_raw(parent_dir_id_str),
                encrypted_path: dir_path.to_path_buf(),
            }),
            Err(e) => {
                eprintln!(
                    "Warning: Failed to recover parent ID for directory at {:?}: {}",
                    dir_path, e
                );
                None
            }
        }
    }
}

/// Debug helper to read and display files in a directory tree
pub fn debug_read_files_in_tree(
    vault_ops: &VaultOperations,
    directory_id: &DirId,
    _dir_name: &str,
    depth: usize,
) -> Result<(), VaultOperationError> {
    let indent = "  ".repeat(depth);

    // List and display files
    let files = vault_ops.list_files(directory_id)?;
    for file in files {
        println!("\n{}📄 {}", indent, file.name);
        println!("{}   Size: {} bytes (encrypted)", indent, file.encrypted_size);

        // For text files, show content preview
        if file.name.ends_with(".txt") || file.name.ends_with(".md")
            || file.name.ends_with(".c") || file.name.ends_with(".rs") {

            match vault_ops.decrypt_file_internal(&file.encrypted_path) {
                Ok(decrypted) => {
                    println!("{}   Decrypted size: {} bytes", indent, decrypted.content.len());

                    let content_str = if decrypted.content.is_empty() {
                        "(empty file)".to_string()
                    } else {
                        let preview_len = decrypted.content.len().min(200);
                        match String::from_utf8(decrypted.content[..preview_len].to_vec()) {
                            Ok(s) => s,
                            Err(_) => "(binary content)".to_string()
                        }
                    };

                    println!("{indent}   Content preview:");
                    for line in content_str.lines().take(5) {
                        println!("{indent}   | {line}");
                    }
                    if decrypted.content.len() > 200 {
                        println!("{indent}   | ... (truncated)");
                    }
                }
                Err(e) => {
                    println!("{indent}   ❌ Failed to decrypt: {e}");
                }
            }
        }
    }

    // Recursively process subdirectories
    let subdirs = vault_ops.list_directories(directory_id)?;
    for subdir in subdirs {
        println!("\n{}📁 {}", indent, subdir.name);
        debug_read_files_in_tree(vault_ops, &subdir.directory_id, &subdir.name, depth + 1)?;
    }

    Ok(())
}
