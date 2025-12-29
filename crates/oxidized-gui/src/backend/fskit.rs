//! FSKit-based filesystem backend (macOS 15.4+)
//!
//! When the `fskit` feature is enabled, this module re-exports the real
//! `FSKitBackend` from `oxidized-fskit`. Otherwise, it provides a stub
//! that reports FSKit as unavailable.
//!
//! # Requirements for FSKit
//!
//! - macOS 15.4 (Sequoia) or later
//! - FSKitBridge.app installed and enabled
//! - `protoc` available at build time (for fskit-rs)
//!
//! # Building with FSKit support
//!
//! ```bash
//! cargo build -p oxidized-gui --features fskit
//! ```

// When the fskit feature is enabled, re-export from oxidized-fskit
#[cfg(feature = "fskit")]
pub use oxidized_fskit::FSKitBackend;

// When the fskit feature is disabled, provide a stub implementation
#[cfg(not(feature = "fskit"))]
mod stub {
    use oxidized_mount_common::{BackendType, MountBackend, MountError, MountHandle};
    use std::path::Path;

    /// FSKit-based mounting backend (stub)
    ///
    /// This is a placeholder when the `fskit` feature is not enabled.
    /// Enable the feature to use the real FSKit backend:
    ///
    /// ```bash
    /// cargo build --features fskit
    /// ```
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FSKitBackend;

    impl FSKitBackend {
        /// Create a new FSKitBackend stub
        pub fn new() -> Self {
            Self
        }
    }

    impl MountBackend for FSKitBackend {
        fn name(&self) -> &'static str {
            "FSKit"
        }

        fn id(&self) -> &'static str {
            "fskit"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            #[cfg(target_os = "macos")]
            {
                Some(
                    "FSKit support requires building with --features fskit. \
                     It also requires macOS 15.4+ and FSKitBridge.app."
                        .to_string(),
                )
            }
            #[cfg(not(target_os = "macos"))]
            {
                Some("FSKit is only available on macOS 15.4 and later.".to_string())
            }
        }

        fn backend_type(&self) -> BackendType {
            BackendType::FSKit
        }

        fn description(&self) -> &'static str {
            "Uses Apple's native FSKit framework (macOS 15.4+)"
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

#[cfg(not(feature = "fskit"))]
pub use stub::FSKitBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_mount_common::MountBackend;

    #[test]
    fn fskit_backend_id() {
        let backend = FSKitBackend::default();
        assert_eq!(backend.id(), "fskit");
        assert_eq!(backend.name(), "FSKit");
    }

    #[cfg(not(feature = "fskit"))]
    #[test]
    fn stub_reports_unavailable() {
        let backend = FSKitBackend;
        // Stub should always be unavailable
        assert!(!backend.is_available());
        assert!(backend.unavailable_reason().is_some());
    }

    #[cfg(feature = "fskit")]
    #[test]
    fn real_backend_availability_check() {
        let backend = FSKitBackend::default();
        // Real backend checks system requirements
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }
}
