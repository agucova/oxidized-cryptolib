//! WebDAV-based filesystem backend
//!
//! When the `webdav` feature is enabled, this module re-exports the real
//! `WebDavBackend` from `oxidized-webdav`. Otherwise, it provides a stub
//! that reports WebDAV as unavailable.
//!
//! # About WebDAV
//!
//! WebDAV is a cross-platform solution that works on all operating systems
//! without requiring kernel extensions. It starts a local HTTP server that
//! exposes the vault contents via the WebDAV protocol.
//!
//! Users can then mount the WebDAV share using:
//! - Windows: `net use Z: http://localhost:8080` or Map Network Drive
//! - macOS: Finder → Go → Connect to Server → `http://localhost:8080`
//! - Linux: File manager or `mount.davfs`
//!
//! # Building with WebDAV support
//!
//! ```bash
//! cargo build -p oxidized-gui --features webdav
//! ```

// When the webdav feature is enabled, re-export from oxidized-webdav
#[cfg(feature = "webdav")]
pub use oxidized_webdav::WebDavBackend;

// When the webdav feature is disabled, provide a stub implementation
#[cfg(not(feature = "webdav"))]
mod stub {
    use oxidized_mount_common::{BackendType, MountBackend, MountError, MountHandle};
    use std::path::Path;

    /// WebDAV-based mounting backend (stub)
    ///
    /// This is a placeholder when the `webdav` feature is not enabled.
    /// Enable the feature to use the real WebDAV backend:
    ///
    /// ```bash
    /// cargo build --features webdav
    /// ```
    #[derive(Debug, Clone, Copy, Default)]
    pub struct WebDavBackend;

    impl WebDavBackend {
        pub fn new() -> Self {
            Self
        }
    }

    impl MountBackend for WebDavBackend {
        fn name(&self) -> &'static str {
            "WebDAV"
        }

        fn id(&self) -> &'static str {
            "webdav"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            Some(
                "WebDAV support requires building with --features webdav.".to_string(),
            )
        }

        fn backend_type(&self) -> BackendType {
            BackendType::WebDav
        }

        fn description(&self) -> &'static str {
            "Starts a local WebDAV server (no kernel extensions required)"
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

#[cfg(not(feature = "webdav"))]
pub use stub::WebDavBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_mount_common::MountBackend;

    #[test]
    fn webdav_backend_id() {
        let backend = WebDavBackend::new();
        assert_eq!(backend.id(), "webdav");
        assert_eq!(backend.name(), "WebDAV");
    }

    #[cfg(not(feature = "webdav"))]
    #[test]
    fn stub_reports_unavailable() {
        let backend = WebDavBackend::new();
        // Stub should always be unavailable
        assert!(!backend.is_available());
        assert!(backend.unavailable_reason().is_some());
    }

    #[cfg(feature = "webdav")]
    #[test]
    fn real_backend_availability_check() {
        let backend = WebDavBackend::new();
        // Real backend checks system requirements
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }
}
