//! Mount backend abstraction
//!
//! This module provides traits for mounting Cryptomator vaults as filesystems,
//! abstracting over different backend implementations (FUSE, FSKit, etc.).
//!
//! # Architecture
//!
//! The mount system is built around two core traits:
//!
//! - [`MountBackend`]: Represents a mounting mechanism (e.g., FUSE, FSKit)
//! - [`MountHandle`]: A handle to a mounted filesystem that controls its lifecycle
//!
//! # Backend Selection
//!
//! Applications can use [`BackendType`] to specify a preferred backend,
//! or use [`first_available_backend()`] to pick the first available one
//! from an ordered list.
//!
//! # Example
//!
//! ```ignore
//! use oxidized_mount_common::{MountBackend, first_available_backend};
//!
//! // Build backends in order of preference
//! let backends: Vec<Box<dyn MountBackend>> = vec![/* ... */];
//!
//! // Get the first available backend
//! let backend = first_available_backend(&backends)?;
//!
//! let handle = backend.mount("my-vault", vault_path, password, mountpoint)?;
//! // ... use the mounted filesystem ...
//! handle.unmount()?;
//! ```

use crate::VaultStats;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Mount options for configuring filesystem behavior.
///
/// These options affect how the filesystem behaves once mounted.
/// Not all backends support all options, but they should gracefully
/// ignore unsupported options.
///
/// # Presets
///
/// Use [`MountOptions::local()`] for vaults on local/fast storage, or
/// [`MountOptions::network()`] (the default) for cloud storage backends.
///
/// # Example
///
/// ```
/// use oxidized_mount_common::MountOptions;
/// use std::time::Duration;
///
/// // Use local preset for a vault on local SSD
/// let local_opts = MountOptions::local();
///
/// // Use network preset with custom TTL
/// let network_opts = MountOptions::network()
///     .with_attr_ttl(Duration::from_secs(120));
///
/// // Custom configuration
/// let custom = MountOptions::default()
///     .with_attr_ttl(Duration::from_secs(30))
///     .with_negative_ttl(Duration::from_secs(10))
///     .with_background_refresh(true);
/// ```
#[derive(Debug, Clone, Default)]
pub struct MountOptions {
    /// Use local mode with shorter cache TTLs.
    ///
    /// When enabled (true):
    /// - Attribute cache TTL: 1 second
    /// - Negative cache TTL: 500ms
    /// - Background refresh: disabled
    ///
    /// When disabled (false, default):
    /// - Attribute cache TTL: 60 seconds
    /// - Negative cache TTL: 30 seconds
    /// - Background refresh: enabled
    ///
    /// Local mode is recommended when the vault is stored on a local/fast
    /// filesystem. Network mode (default) is optimized for cloud storage
    /// backends like Google Drive or Dropbox.
    pub local_mode: bool,

    /// Custom attribute cache TTL, overriding the local/network mode default.
    ///
    /// Default: 1 second (local) or 60 seconds (network).
    pub attr_ttl: Option<Duration>,

    /// Custom negative cache TTL for ENOENT results.
    ///
    /// Default: 500ms (local) or 30 seconds (network).
    pub negative_ttl: Option<Duration>,

    /// Enable background directory refresh.
    ///
    /// When enabled, `readdir` returns cached results immediately and
    /// refreshes in the background. This keeps file browsers responsive
    /// even when the underlying storage is slow.
    ///
    /// Default: false (local) or true (network).
    pub background_refresh: Option<bool>,

    /// Maximum concurrent I/O operations for directory listings.
    ///
    /// Higher values improve throughput on high-latency backends but
    /// may overwhelm rate-limited services.
    ///
    /// Default: 32.
    pub concurrency_limit: Option<usize>,
}

impl MountOptions {
    /// Create options optimized for local filesystem vaults.
    ///
    /// Uses shorter cache TTLs (1s / 500ms) for fresher metadata
    /// and disables background refresh.
    pub fn local() -> Self {
        Self {
            local_mode: true,
            attr_ttl: None,
            negative_ttl: None,
            background_refresh: None,
            concurrency_limit: None,
        }
    }

    /// Create options optimized for network filesystem vaults (default).
    ///
    /// Uses longer cache TTLs (60s / 30s) and enables background refresh
    /// for responsive UI with high-latency cloud storage.
    pub fn network() -> Self {
        Self::default()
    }

    /// Set a custom attribute cache TTL.
    #[must_use]
    pub fn with_attr_ttl(mut self, ttl: Duration) -> Self {
        self.attr_ttl = Some(ttl);
        self
    }

    /// Set a custom negative cache TTL.
    #[must_use]
    pub fn with_negative_ttl(mut self, ttl: Duration) -> Self {
        self.negative_ttl = Some(ttl);
        self
    }

    /// Enable or disable background directory refresh.
    #[must_use]
    pub fn with_background_refresh(mut self, enabled: bool) -> Self {
        self.background_refresh = Some(enabled);
        self
    }

    /// Set the concurrency limit for directory operations.
    #[must_use]
    pub fn with_concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = Some(limit);
        self
    }

    /// Get the effective attribute TTL based on mode and overrides.
    ///
    /// Returns the custom TTL if set, otherwise the mode default.
    pub fn effective_attr_ttl(&self) -> Duration {
        self.attr_ttl.unwrap_or(if self.local_mode {
            crate::LOCAL_TTL
        } else {
            crate::DEFAULT_TTL
        })
    }

    /// Get the effective negative cache TTL based on mode and overrides.
    ///
    /// Returns the custom TTL if set, otherwise the mode default.
    pub fn effective_negative_ttl(&self) -> Duration {
        self.negative_ttl.unwrap_or(if self.local_mode {
            crate::LOCAL_NEGATIVE_TTL
        } else {
            crate::DEFAULT_NEGATIVE_TTL
        })
    }

    /// Get the effective background refresh setting based on mode and overrides.
    ///
    /// Returns the custom setting if set, otherwise the mode default.
    pub fn effective_background_refresh(&self) -> bool {
        self.background_refresh.unwrap_or(!self.local_mode)
    }

    /// Get the effective concurrency limit.
    ///
    /// Returns the custom limit if set, otherwise the default (32).
    pub fn effective_concurrency_limit(&self) -> usize {
        self.concurrency_limit.unwrap_or(32)
    }
}

/// Errors that can occur during mount operations
#[derive(Error, Debug)]
pub enum MountError {
    /// Failed to create the filesystem (e.g., wrong password, corrupted vault)
    #[error("Failed to create filesystem: {0}")]
    FilesystemCreation(String),

    /// OS-level mount operation failed
    #[error("Failed to mount: {0}")]
    Mount(#[from] std::io::Error),

    /// The specified mount point doesn't exist
    #[error("Mount point does not exist: {0}")]
    MountPointNotFound(PathBuf),

    /// Attempted to unmount a vault that isn't mounted
    #[error("Vault is not mounted")]
    NotMounted,

    /// The requested backend is not available on this system
    #[error("Backend not available: {0}")]
    BackendUnavailable(String),

    /// Unmount operation failed
    #[error("Unmount failed: {0}")]
    UnmountFailed(String),
}

/// A handle to a mounted filesystem
///
/// This handle controls the lifecycle of a mounted vault. When dropped,
/// the filesystem should be automatically unmounted.
///
/// # Lifecycle
///
/// 1. Created by [`MountBackend::mount()`]
/// 2. Filesystem is accessible at [`mountpoint()`](MountHandle::mountpoint)
/// 3. Call [`unmount()`](MountHandle::unmount) for explicit cleanup, or drop the handle
///
/// # Drop Behavior
///
/// Implementations must ensure that dropping the handle triggers an unmount,
/// even if `unmount()` was not explicitly called. This prevents orphaned mounts.
pub trait MountHandle: Send {
    /// Get the path where the filesystem is mounted
    fn mountpoint(&self) -> &Path;

    /// Explicitly unmount the filesystem
    ///
    /// This consumes the handle and performs a clean unmount. If this method
    /// is not called, dropping the handle will also trigger an unmount.
    ///
    /// # Errors
    ///
    /// Returns an error if the unmount operation fails (e.g., filesystem busy).
    fn unmount(self: Box<Self>) -> Result<(), MountError>;

    /// Force unmount the filesystem, even if it's busy
    ///
    /// This attempts a more aggressive unmount that may succeed even when
    /// files are open or processes are using the filesystem. Use with caution
    /// as this may cause data loss in applications with unsaved changes.
    ///
    /// # Platform Behavior
    ///
    /// - **macOS**: Uses `diskutil unmount force` or `umount -f`
    /// - **Linux**: Uses `fusermount -u -z` (lazy unmount) or `umount -l`
    ///
    /// # Default Implementation
    ///
    /// Falls back to regular [`unmount()`](MountHandle::unmount) if not overridden.
    fn force_unmount(self: Box<Self>) -> Result<(), MountError>;

    /// Get statistics for this mounted filesystem
    ///
    /// Returns an `Arc<VaultStats>` that tracks I/O operations on the mount.
    /// The stats are shared with the filesystem and update in real-time.
    ///
    /// # Default Implementation
    ///
    /// Returns `None` if the backend doesn't support statistics.
    fn stats(&self) -> Option<Arc<VaultStats>> {
        None
    }
}

/// A backend that can mount Cryptomator vaults as filesystems
///
/// Implementations provide different mounting mechanisms while presenting
/// a unified interface to applications.
///
/// # Available Backends
///
/// - **FUSE**: Uses macFUSE (macOS) or libfuse (Linux). Widely compatible.
/// - **FSKit**: Apple's native framework (macOS 15.4+). Better integration, no kernel extension.
///
/// # Thread Safety
///
/// Backends must be `Send + Sync` to allow sharing across threads.
/// Mount operations may block and should be run on a background thread.
pub trait MountBackend: Send + Sync {
    /// Human-readable name for this backend
    ///
    /// Used in UI elements and logs. Examples: "FUSE", "FSKit"
    fn name(&self) -> &'static str;

    /// Unique identifier for this backend
    ///
    /// Used for configuration and serialization. Examples: "fuse", "fskit"
    fn id(&self) -> &'static str;

    /// Check if this backend is available on the current system
    ///
    /// This should verify that all required dependencies are present:
    /// - FUSE: macFUSE installed (macOS) or /dev/fuse exists (Linux)
    /// - FSKit: Running macOS 15.4 or later
    fn is_available(&self) -> bool;

    /// Get a human-readable explanation of why the backend is unavailable
    ///
    /// Returns `None` if the backend is available. The message should help
    /// users understand how to make the backend available (e.g., "Install macFUSE").
    fn unavailable_reason(&self) -> Option<String>;

    /// Get the backend type enum value
    fn backend_type(&self) -> BackendType;

    /// Get a brief description of this backend
    fn description(&self) -> &'static str;

    /// Mount a Cryptomator vault at the specified location
    ///
    /// This creates an encrypted filesystem view of the vault. The vault
    /// password is used to derive decryption keys.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - Unique identifier for tracking this mount
    /// * `vault_path` - Path to the Cryptomator vault directory (containing `vault.cryptomator`)
    /// * `password` - Vault password for key derivation
    /// * `mountpoint` - Directory where the decrypted view will appear
    ///
    /// # Errors
    ///
    /// - [`MountError::FilesystemCreation`] - Wrong password or corrupted vault
    /// - [`MountError::Mount`] - OS-level mount failure
    /// - [`MountError::MountPointNotFound`] - Mount point doesn't exist
    /// - [`MountError::BackendUnavailable`] - Backend not available on this system
    ///
    /// # Security
    ///
    /// The password is used only during this call for key derivation.
    /// Implementations should not store the password.
    fn mount(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError>;

    /// Mount a Cryptomator vault with custom options.
    ///
    /// This is like [`mount()`](MountBackend::mount) but allows passing
    /// configuration options like local mode or custom cache TTLs.
    ///
    /// # Default Implementation
    ///
    /// Falls back to [`mount()`](MountBackend::mount), ignoring the options.
    /// Backends that support options should override this method.
    fn mount_with_options(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
        _options: &MountOptions,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        // Default: ignore options and use standard mount
        self.mount(vault_id, vault_path, password, mountpoint)
    }
}

/// Available backend types for vault mounting
///
/// This enum is used for configuration and preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    /// FUSE-based mounting
    ///
    /// Uses macFUSE on macOS or libfuse on Linux. This is the most
    /// widely compatible option but requires additional software:
    /// - macOS: Install [macFUSE](https://osxfuse.github.io/)
    /// - Linux: Usually pre-installed (`/dev/fuse`)
    #[default]
    Fuse,

    /// FSKit-based mounting (macOS only)
    ///
    /// Uses Apple's native FSKit framework, available on macOS 15.4+.
    /// Benefits:
    /// - No kernel extension required
    /// - Better system integration
    /// - Survives sleep/wake cycles more reliably
    FSKit,

    /// WebDAV-based mounting
    ///
    /// Starts a local WebDAV server instead of kernel-level mounting.
    /// Users mount via:
    /// - macOS Finder: Cmd+K → enter server URL
    /// - Windows Explorer: Map Network Drive → enter URL
    /// - Linux: File manager or mount.davfs
    ///
    /// Benefits:
    /// - No kernel extensions required (no macFUSE)
    /// - No macOS version requirements (unlike FSKit)
    /// - Cross-platform (works anywhere with WebDAV client)
    /// - Easier debugging (standard HTTP tools)
    WebDav,

    /// NFS-based mounting
    ///
    /// Starts a local NFSv3 server and uses the system's NFS client.
    /// Mounts automatically via `mount_nfs` (macOS) or `mount.nfs` (Linux).
    ///
    /// Benefits:
    /// - No kernel extensions required (uses built-in NFS client)
    /// - No macOS version requirements (unlike FSKit)
    /// - Native async support for better concurrency
    /// - Stateless protocol (simpler than FUSE)
    Nfs,
}

impl BackendType {
    /// Get the display name for UI presentation
    pub fn display_name(&self) -> &'static str {
        match self {
            BackendType::Fuse => "FUSE",
            BackendType::FSKit => "FSKit",
            BackendType::WebDav => "WebDAV",
            BackendType::Nfs => "NFS",
        }
    }

    /// Get a user-friendly description of this backend
    pub fn description(&self) -> &'static str {
        match self {
            BackendType::Fuse => "Uses macFUSE (macOS) or libfuse (Linux) for filesystem mounting",
            BackendType::FSKit => "Uses Apple's native FSKit framework (macOS 15.4+)",
            BackendType::WebDav => "Starts a local WebDAV server (no kernel extensions required)",
            BackendType::Nfs => "Uses local NFSv3 server with system NFS client (no kernel extensions required)",
        }
    }

    /// Get all backend types
    pub fn all() -> &'static [BackendType] {
        &[BackendType::Fuse, BackendType::FSKit, BackendType::WebDav, BackendType::Nfs]
    }

    /// Check if this backend supports fsync/F_FULLFSYNC operations.
    ///
    /// On macOS, the WebDAV filesystem driver doesn't support `F_FULLFSYNC`
    /// (used by `sync_all()`), returning `ENOTTY` (errno 25). This method
    /// allows callers to check support before calling sync operations.
    ///
    /// # Returns
    ///
    /// - `true`: Backend supports fsync operations normally
    /// - `false`: Backend may return ENOTTY for fsync operations
    pub fn supports_fsync(&self) -> bool {
        match self {
            BackendType::Fuse => true,
            BackendType::FSKit => true,
            BackendType::WebDav => false, // macOS WebDAV driver returns ENOTTY
            BackendType::Nfs => true,
        }
    }
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Sync a file to disk, gracefully handling backends that don't support F_FULLFSYNC.
///
/// On macOS, `sync_all()` uses `fcntl(F_FULLFSYNC)` which some filesystem drivers
/// (notably WebDAV) don't support, returning `ENOTTY` (errno 25). This function
/// handles that case gracefully by falling back to `sync_data()`, and if that also
/// fails with ENOTTY, considers the sync successful (the write completed, just
/// without the durability guarantee).
///
/// # Arguments
///
/// * `file` - The file to sync
///
/// # Returns
///
/// * `Ok(true)` - File was synced with full durability guarantee
/// * `Ok(false)` - File was written but fsync isn't supported (e.g., WebDAV)
/// * `Err(_)` - An actual I/O error occurred
///
/// # Example
///
/// ```ignore
/// use oxidized_mount_common::safe_sync;
/// use std::fs::File;
/// use std::io::Write;
///
/// let mut file = File::create("/path/to/file")?;
/// file.write_all(b"content")?;
///
/// match safe_sync(&file) {
///     Ok(true) => println!("Synced with durability guarantee"),
///     Ok(false) => println!("Written but fsync not supported"),
///     Err(e) => eprintln!("I/O error: {}", e),
/// }
/// ```
pub fn safe_sync(file: &File) -> io::Result<bool> {
    // ENOTTY - "Inappropriate ioctl for device"
    // Returned by macOS WebDAV driver for F_FULLFSYNC
    const ENOTTY: i32 = 25;

    match file.sync_all() {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(ENOTTY) => {
            // F_FULLFSYNC not supported, try sync_data
            match file.sync_data() {
                Ok(()) => Ok(false), // Partial sync succeeded
                Err(e2) if e2.raw_os_error() == Some(ENOTTY) => {
                    // Neither works - backend doesn't support any sync
                    // The data was written, just not with durability guarantee
                    Ok(false)
                }
                Err(e2) => Err(e2),
            }
        }
        Err(e) => Err(e),
    }
}

/// Serializable information about a backend's availability
///
/// This struct provides a snapshot of a backend's status that can be
/// serialized for configuration or display purposes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackendInfo {
    /// Backend identifier (e.g., "fuse", "fskit")
    pub id: String,
    /// Human-readable name (e.g., "FUSE", "FSKit")
    pub name: String,
    /// Backend type enum value
    pub backend_type: BackendType,
    /// Brief description of the backend
    pub description: String,
    /// Whether the backend is available on this system
    pub available: bool,
    /// Why the backend is unavailable, if applicable
    pub unavailable_reason: Option<String>,
}

/// Select a specific backend by type from a list
///
/// Returns an error if the requested backend is not available.
///
/// # Arguments
///
/// * `backends` - List of available backend implementations
/// * `backend_type` - The type of backend to select
pub fn select_backend(
    backends: &[Box<dyn MountBackend>],
    backend_type: BackendType,
) -> Result<&dyn MountBackend, MountError> {
    let id = match backend_type {
        BackendType::Fuse => "fuse",
        BackendType::FSKit => "fskit",
        BackendType::WebDav => "webdav",
        BackendType::Nfs => "nfs",
    };

    backends
        .iter()
        .find(|b| b.id() == id)
        .map(|b| b.as_ref())
        .filter(|b| b.is_available())
        .ok_or_else(|| {
            let reason = backends
                .iter()
                .find(|b| b.id() == id)
                .and_then(|b| b.unavailable_reason())
                .unwrap_or_else(|| "Backend not found".to_string());
            MountError::BackendUnavailable(reason)
        })
}

/// Get the first available backend from an ordered list
///
/// The caller controls priority by ordering the backends list.
/// Returns an error if no backend is available.
///
/// # Arguments
///
/// * `backends` - List of backend implementations, ordered by preference
pub fn first_available_backend(
    backends: &[Box<dyn MountBackend>],
) -> Result<&dyn MountBackend, MountError> {
    backends
        .iter()
        .find(|b| b.is_available())
        .map(|b| b.as_ref())
        .ok_or_else(|| {
            let reasons: Vec<String> = backends
                .iter()
                .filter_map(|b| b.unavailable_reason())
                .collect();
            MountError::BackendUnavailable(if reasons.is_empty() {
                "No backends available".to_string()
            } else {
                reasons.join("; ")
            })
        })
}

/// Get information about all backends in a list
///
/// Returns a serializable snapshot of each backend's availability status.
pub fn list_backend_info(backends: &[Box<dyn MountBackend>]) -> Vec<BackendInfo> {
    backends
        .iter()
        .map(|b| BackendInfo {
            id: b.id().to_string(),
            name: b.name().to_string(),
            backend_type: b.backend_type(),
            description: b.description().to_string(),
            available: b.is_available(),
            unavailable_reason: b.unavailable_reason(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_type_serialization() {
        assert_eq!(
            serde_json::to_string(&BackendType::Fuse).unwrap(),
            "\"fuse\""
        );
        assert_eq!(
            serde_json::to_string(&BackendType::FSKit).unwrap(),
            "\"fskit\""
        );
        assert_eq!(
            serde_json::to_string(&BackendType::WebDav).unwrap(),
            "\"webdav\""
        );
        assert_eq!(
            serde_json::to_string(&BackendType::Nfs).unwrap(),
            "\"nfs\""
        );
    }

    #[test]
    fn backend_type_deserialization() {
        assert_eq!(
            serde_json::from_str::<BackendType>("\"fuse\"").unwrap(),
            BackendType::Fuse
        );
        assert_eq!(
            serde_json::from_str::<BackendType>("\"fskit\"").unwrap(),
            BackendType::FSKit
        );
        assert_eq!(
            serde_json::from_str::<BackendType>("\"webdav\"").unwrap(),
            BackendType::WebDav
        );
        assert_eq!(
            serde_json::from_str::<BackendType>("\"nfs\"").unwrap(),
            BackendType::Nfs
        );
    }

    #[test]
    fn backend_type_default() {
        assert_eq!(BackendType::default(), BackendType::Fuse);
    }

    #[test]
    fn mount_options_default_is_network() {
        let opts = MountOptions::default();
        assert!(!opts.local_mode);
        assert!(opts.attr_ttl.is_none());
        assert!(opts.negative_ttl.is_none());
        assert!(opts.background_refresh.is_none());
        assert!(opts.concurrency_limit.is_none());
    }

    #[test]
    fn mount_options_local_preset() {
        let opts = MountOptions::local();
        assert!(opts.local_mode);
        assert!(opts.attr_ttl.is_none()); // Uses mode default
        assert!(opts.negative_ttl.is_none());
        assert!(opts.background_refresh.is_none());
    }

    #[test]
    fn mount_options_network_preset() {
        let opts = MountOptions::network();
        assert!(!opts.local_mode);
        // network() is just default()
        assert!(opts.attr_ttl.is_none());
    }

    #[test]
    fn mount_options_effective_ttl_local_mode() {
        use crate::{LOCAL_NEGATIVE_TTL, LOCAL_TTL};

        let opts = MountOptions::local();
        assert_eq!(opts.effective_attr_ttl(), LOCAL_TTL);
        assert_eq!(opts.effective_negative_ttl(), LOCAL_NEGATIVE_TTL);
        assert!(!opts.effective_background_refresh());
    }

    #[test]
    fn mount_options_effective_ttl_network_mode() {
        use crate::{DEFAULT_NEGATIVE_TTL, DEFAULT_TTL};

        let opts = MountOptions::network();
        assert_eq!(opts.effective_attr_ttl(), DEFAULT_TTL);
        assert_eq!(opts.effective_negative_ttl(), DEFAULT_NEGATIVE_TTL);
        assert!(opts.effective_background_refresh());
    }

    #[test]
    fn mount_options_custom_overrides_mode() {
        use std::time::Duration;

        let custom_attr = Duration::from_secs(120);
        let custom_neg = Duration::from_secs(15);

        // Custom values should override local mode defaults
        let opts = MountOptions::local()
            .with_attr_ttl(custom_attr)
            .with_negative_ttl(custom_neg)
            .with_background_refresh(true);

        assert_eq!(opts.effective_attr_ttl(), custom_attr);
        assert_eq!(opts.effective_negative_ttl(), custom_neg);
        assert!(opts.effective_background_refresh());
    }

    #[test]
    fn mount_options_concurrency_limit() {
        let opts = MountOptions::default();
        assert_eq!(opts.effective_concurrency_limit(), 32); // Default

        let custom = MountOptions::default().with_concurrency_limit(16);
        assert_eq!(custom.effective_concurrency_limit(), 16);
    }

    #[test]
    fn mount_options_builder_chain() {
        use std::time::Duration;

        let opts = MountOptions::default()
            .with_attr_ttl(Duration::from_secs(90))
            .with_negative_ttl(Duration::from_secs(45))
            .with_background_refresh(false)
            .with_concurrency_limit(64);

        assert_eq!(opts.effective_attr_ttl(), Duration::from_secs(90));
        assert_eq!(opts.effective_negative_ttl(), Duration::from_secs(45));
        assert!(!opts.effective_background_refresh());
        assert_eq!(opts.effective_concurrency_limit(), 64);
    }
}
