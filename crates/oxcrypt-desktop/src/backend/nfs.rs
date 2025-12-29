//! NFS-based filesystem backend
//!
//! When the `nfs` feature is enabled, this module re-exports the real
//! `NfsBackend` from `oxcrypt-nfs`. Otherwise, it provides a stub
//! that reports NFS as unavailable.
//!
//! # About NFS
//!
//! NFS is a cross-platform solution for Unix-like systems that works without
//! requiring kernel extensions like FUSE. It starts a local NFSv3 server that
//! exposes the vault contents via the NFS protocol.
//!
//! The operating system's built-in NFS client is then used to mount the share:
//! - macOS: Uses `mount_nfs` (built-in)
//! - Linux: Uses `mount.nfs` (from nfs-common package)
//!
//! # Building with NFS support
//!
//! ```bash
//! cargo build -p oxcrypt-desktop --features nfs
//! ```

// When the nfs feature is enabled, re-export from oxcrypt-nfs
#[cfg(feature = "nfs")]
pub use oxcrypt_nfs::NfsBackend;

// When the nfs feature is disabled, provide a stub implementation
#[cfg(not(feature = "nfs"))]
mod stub {
    use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle};
    use std::path::Path;

    /// NFS-based mounting backend (stub)
    ///
    /// This is a placeholder when the `nfs` feature is not enabled.
    /// Enable the feature to use the real NFS backend:
    ///
    /// ```bash
    /// cargo build --features nfs
    /// ```
    #[derive(Debug, Clone, Copy, Default)]
    pub struct NfsBackend;

    impl NfsBackend {
        pub fn new() -> Self {
            Self
        }
    }

    impl MountBackend for NfsBackend {
        fn name(&self) -> &'static str {
            "NFS"
        }

        fn id(&self) -> &'static str {
            "nfs"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            Some("NFS support requires building with --features nfs.".to_string())
        }

        fn backend_type(&self) -> BackendType {
            BackendType::Nfs
        }

        fn description(&self) -> &'static str {
            "Starts a local NFS server (no kernel extensions required)"
        }

        fn mount(
            &self,
            _vault_id: &str,
            _vault_path: &Path,
            _password: &str,
            _mountpoint: &Path,
        ) -> Result<Box<dyn MountHandle>, MountError> {
            Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ))
        }
    }
}

#[cfg(not(feature = "nfs"))]
pub use stub::NfsBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use oxcrypt_mount::MountBackend;

    #[test]
    fn nfs_backend_id() {
        let backend = NfsBackend::new();
        assert_eq!(backend.id(), "nfs");
        assert_eq!(backend.name(), "NFS");
    }

    #[cfg(not(feature = "nfs"))]
    #[test]
    fn stub_reports_unavailable() {
        let backend = NfsBackend::new();
        // Stub should always be unavailable
        assert!(!backend.is_available());
        assert!(backend.unavailable_reason().is_some());
    }

    #[cfg(feature = "nfs")]
    #[test]
    fn real_backend_availability_check() {
        let backend = NfsBackend::new();
        // Real backend checks system requirements
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }
}
