//! FUSE-based filesystem backend
//!
//! When the `fuse` feature is enabled, this module re-exports the real
//! `FuseBackend` from `oxidized-fuse`. Otherwise, it provides a stub
//! that reports FUSE as unavailable.
//!
//! # Requirements for FUSE
//!
//! - macOS: macFUSE installed (https://osxfuse.github.io/)
//! - Linux: libfuse3 installed (usually via package manager)
//! - Windows: Not supported (FUSE is Unix-only)
//!
//! # Building with FUSE support
//!
//! ```bash
//! cargo build -p oxidized-gui --features fuse
//! ```

// When the fuse feature is enabled, re-export from oxidized-fuse
#[cfg(feature = "fuse")]
pub use oxidized_fuse::FuseBackend;

// When the fuse feature is disabled, provide a stub implementation
#[cfg(not(feature = "fuse"))]
mod stub {
    use oxidized_cryptolib::{BackendType, MountBackend, MountError, MountHandle};
    use std::path::Path;

    /// FUSE-based mounting backend (stub)
    ///
    /// This is a placeholder when the `fuse` feature is not enabled.
    /// Enable the feature to use the real FUSE backend:
    ///
    /// ```bash
    /// cargo build --features fuse
    /// ```
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FuseBackend;

    impl FuseBackend {
        pub fn new() -> Self {
            Self
        }
    }

    impl MountBackend for FuseBackend {
        fn name(&self) -> &'static str {
            "FUSE"
        }

        fn id(&self) -> &'static str {
            "fuse"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            #[cfg(target_os = "windows")]
            {
                Some("FUSE is not available on Windows. Use WebDAV backend instead.".to_string())
            }
            #[cfg(target_os = "macos")]
            {
                Some(
                    "FUSE support requires building with --features fuse. \
                     It also requires macFUSE to be installed."
                        .to_string(),
                )
            }
            #[cfg(target_os = "linux")]
            {
                Some(
                    "FUSE support requires building with --features fuse. \
                     It also requires libfuse3 to be installed."
                        .to_string(),
                )
            }
            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            {
                Some("FUSE support requires building with --features fuse.".to_string())
            }
        }

        fn backend_type(&self) -> BackendType {
            BackendType::Fuse
        }

        fn description(&self) -> &'static str {
            "Uses macFUSE (macOS) or libfuse (Linux) for filesystem mounting"
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

#[cfg(not(feature = "fuse"))]
pub use stub::FuseBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_cryptolib::MountBackend;

    #[test]
    fn fuse_backend_id() {
        let backend = FuseBackend::new();
        assert_eq!(backend.id(), "fuse");
        assert_eq!(backend.name(), "FUSE");
    }

    #[cfg(not(feature = "fuse"))]
    #[test]
    fn stub_reports_unavailable() {
        let backend = FuseBackend::new();
        // Stub should always be unavailable
        assert!(!backend.is_available());
        assert!(backend.unavailable_reason().is_some());
    }

    #[cfg(feature = "fuse")]
    #[test]
    fn real_backend_availability_check() {
        let backend = FuseBackend::new();
        // Real backend checks system requirements
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }
}
