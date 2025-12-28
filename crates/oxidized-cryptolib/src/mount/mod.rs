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
//! Applications can use [`BackendType`] to let users choose their preferred
//! backend, with automatic fallback to available alternatives.
//!
//! # Example
//!
//! ```ignore
//! use oxidized_cryptolib::mount::{MountBackend, BackendType};
//!
//! // Get the appropriate backend for the platform
//! let backend = get_backend(BackendType::Auto);
//!
//! if backend.is_available() {
//!     let handle = backend.mount("my-vault", vault_path, password, mountpoint)?;
//!     // ... use the mounted filesystem ...
//!     handle.unmount()?;
//! }
//! ```

use std::path::{Path, PathBuf};
use thiserror::Error;

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
}

/// Available backend types for vault mounting
///
/// This enum is used for configuration and preferences. Applications can
/// store the user's preferred backend and use [`BackendType::Auto`] for
/// automatic selection.
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

    /// Automatically select the best available backend
    ///
    /// Selection priority:
    /// 1. FSKit (if available on macOS 15.4+)
    /// 2. FUSE (if installed)
    /// 3. Error if nothing available
    Auto,
}

impl BackendType {
    /// Get the display name for UI presentation
    pub fn display_name(&self) -> &'static str {
        match self {
            BackendType::Fuse => "FUSE",
            BackendType::FSKit => "FSKit",
            BackendType::Auto => "Automatic",
        }
    }

    /// Get a user-friendly description of this backend
    pub fn description(&self) -> &'static str {
        match self {
            BackendType::Fuse => "Uses macFUSE (macOS) or libfuse (Linux) for filesystem mounting",
            BackendType::FSKit => "Uses Apple's native FSKit framework (macOS 15.4+)",
            BackendType::Auto => "Automatically selects the best available backend",
        }
    }

    /// Get all backend types (excluding Auto)
    pub fn all_backends() -> &'static [BackendType] {
        &[BackendType::Fuse, BackendType::FSKit]
    }
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
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
            serde_json::to_string(&BackendType::Auto).unwrap(),
            "\"auto\""
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
    }

    #[test]
    fn backend_type_default() {
        assert_eq!(BackendType::default(), BackendType::Fuse);
    }
}
