//! File Provider-based filesystem backend (macOS 13+)
//!
//! When the `fileprovider` feature is enabled, this module re-exports the real
//! `FileProviderBackend` from `oxcrypt-fileprovider`. Otherwise, it provides a stub
//! that reports File Provider as unavailable.
//!
//! # Requirements for File Provider
//!
//! - macOS 13 (Ventura) or later
//! - File Provider extension enabled in System Settings
//!
//! # Building with File Provider support
//!
//! ```bash
//! cargo build -p oxcrypt-desktop --features fileprovider
//! ```

// When the fileprovider feature is enabled, re-export from oxcrypt-fileprovider
#[cfg(feature = "fileprovider")]
pub use oxcrypt_fileprovider::FileProviderBackend;

// When the fileprovider feature is disabled, provide a stub implementation
#[cfg(not(feature = "fileprovider"))]
mod stub {
    use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle};
    use std::path::Path;

    /// File Provider-based mounting backend (stub)
    ///
    /// This is a placeholder when the `fileprovider` feature is not enabled.
    /// Enable the feature to use the real File Provider backend:
    ///
    /// ```bash
    /// cargo build --features fileprovider
    /// ```
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FileProviderBackend;

    impl FileProviderBackend {
        /// Create a new FileProviderBackend stub
        pub fn new() -> Self {
            Self
        }
    }

    impl MountBackend for FileProviderBackend {
        fn name(&self) -> &'static str {
            "File Provider"
        }

        fn id(&self) -> &'static str {
            "fileprovider"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            #[cfg(target_os = "macos")]
            {
                Some(
                    "File Provider support requires building with --features fileprovider. \
                     It also requires macOS 13+ and the File Provider extension to be enabled."
                        .to_string(),
                )
            }
            #[cfg(not(target_os = "macos"))]
            {
                Some("File Provider is only available on macOS 13 (Ventura) and later.".to_string())
            }
        }

        fn backend_type(&self) -> BackendType {
            BackendType::FileProvider
        }

        fn description(&self) -> &'static str {
            "Uses Apple File Provider API for cloud storage integration (macOS 13+)"
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

#[cfg(not(feature = "fileprovider"))]
pub use stub::FileProviderBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use oxcrypt_mount::MountBackend;

    #[test]
    fn fileprovider_backend_id() {
        let backend = FileProviderBackend::default();
        assert_eq!(backend.id(), "fileprovider");
        assert_eq!(backend.name(), "File Provider");
    }

    #[cfg(not(feature = "fileprovider"))]
    #[test]
    fn stub_reports_unavailable() {
        let backend = FileProviderBackend;
        // Stub should always be unavailable
        assert!(!backend.is_available());
        assert!(backend.unavailable_reason().is_some());
    }

    #[cfg(feature = "fileprovider")]
    #[test]
    fn real_backend_availability_check() {
        let backend = FileProviderBackend::default();
        // Real backend checks system requirements
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }
}
