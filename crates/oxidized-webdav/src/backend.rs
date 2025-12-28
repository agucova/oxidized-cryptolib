//! WebDAV mount backend implementation.
//!
//! This module implements the `MountBackend` trait from `oxidized-cryptolib`
//! to provide WebDAV-based mounting as an alternative to FUSE and FSKit.

use crate::filesystem::CryptomatorWebDav;
use crate::server::{auto_mount_macos, unmount_macos, ServerConfig, WebDavServer};
use oxidized_cryptolib::mount::{BackendType, MountBackend, MountError, MountHandle};
use std::path::{Path, PathBuf};
use tokio::runtime::Runtime;
use tracing::{debug, info, warn};

/// WebDAV-based mounting backend.
///
/// Instead of kernel-level mounting like FUSE or FSKit, this backend
/// starts a local WebDAV server. Users can mount via:
/// - macOS Finder: Cmd+K → enter server URL
/// - Windows Explorer: Map Network Drive → enter URL
/// - Linux: File manager or mount.davfs
///
/// # Advantages
///
/// - No kernel extensions required (no macFUSE needed)
/// - No macOS version requirements (unlike FSKit)
/// - Cross-platform (works anywhere with WebDAV client)
/// - Easier debugging (standard HTTP tools)
///
/// # Limitations
///
/// - HTTP overhead vs kernel-level performance
/// - macOS Finder has some UTF-8 quirks with WebDAV
#[derive(Debug, Clone)]
pub struct WebDavBackend {
    /// Server configuration.
    config: ServerConfig,
}

impl Default for WebDavBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl WebDavBackend {
    /// Create a new WebDAV backend with default configuration.
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
        }
    }

    /// Set the port for the WebDAV server.
    ///
    /// Use 0 for auto-assignment (recommended).
    pub fn with_port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Set the bind address for the WebDAV server.
    ///
    /// Default is localhost (127.0.0.1) for security.
    pub fn with_bind_address(mut self, addr: std::net::IpAddr) -> Self {
        self.config.bind_address = addr;
        self
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
        // WebDAV is always available - it's just HTTP
        true
    }

    fn unavailable_reason(&self) -> Option<String> {
        // Always available
        None
    }

    fn backend_type(&self) -> BackendType {
        BackendType::WebDav
    }

    fn description(&self) -> &'static str {
        "Starts a local WebDAV server (no kernel extensions required)"
    }

    fn mount(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        info!(
            vault_id = %vault_id,
            vault_path = %vault_path.display(),
            mountpoint = %mountpoint.display(),
            "Mounting vault via WebDAV"
        );

        // Create a new Tokio runtime for the server
        let runtime = Runtime::new().map_err(|e| {
            MountError::Mount(std::io::Error::other(format!(
                "Failed to create tokio runtime: {}",
                e
            )))
        })?;

        // Create the filesystem
        let fs = CryptomatorWebDav::open(vault_path, password)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Start the server
        let config = self.config.clone();
        let server = runtime.block_on(async {
            WebDavServer::start(fs, config).await
        }).map_err(|e| {
            MountError::Mount(std::io::Error::other(format!(
                "Failed to start WebDAV server: {}",
                e
            )))
        })?;

        let url = server.url();
        info!(url = %url, "WebDAV server started");

        // Attempt auto-mount on macOS
        let auto_mounted = if mountpoint.exists() || mountpoint.parent().map(|p| p.exists()).unwrap_or(false) {
            runtime.block_on(async {
                match auto_mount_macos(&url, mountpoint).await {
                    Ok(()) => {
                        info!(mountpoint = %mountpoint.display(), "Auto-mounted successfully");
                        true
                    }
                    Err(e) => {
                        warn!(error = %e, "Auto-mount failed, mount manually using: {}", url);
                        false
                    }
                }
            })
        } else {
            debug!("Mountpoint doesn't exist, skipping auto-mount");
            false
        };

        Ok(Box::new(WebDavMountHandle {
            server: Some(server),
            runtime: Some(runtime),
            url,
            mountpoint: mountpoint.to_path_buf(),
            auto_mounted,
        }))
    }
}

/// Handle to a running WebDAV mount.
pub struct WebDavMountHandle {
    /// The WebDAV server.
    server: Option<WebDavServer>,
    /// The Tokio runtime.
    runtime: Option<Runtime>,
    /// The server URL.
    url: String,
    /// The mountpoint path.
    mountpoint: PathBuf,
    /// Whether auto-mount succeeded.
    auto_mounted: bool,
}

impl WebDavMountHandle {
    /// Get the server URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl MountHandle for WebDavMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        info!(url = %self.url, "Unmounting WebDAV");

        // Unmount from macOS if we auto-mounted
        if self.auto_mounted && let Err(e) = unmount_macos(&self.mountpoint) {
            warn!(error = %e, "Failed to unmount from macOS");
        }

        // Stop the server
        if let (Some(server), Some(runtime)) = (self.server.take(), self.runtime.take()) {
            runtime.block_on(async {
                server.stop().await;
            });
        }

        info!("WebDAV unmounted successfully");
        Ok(())
    }
}

impl Drop for WebDavMountHandle {
    fn drop(&mut self) {
        // Ensure cleanup even if unmount() wasn't called
        if self.auto_mounted {
            let _ = unmount_macos(&self.mountpoint);
        }

        // Server will be stopped by its own Drop impl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_metadata() {
        let backend = WebDavBackend::new();
        assert_eq!(backend.name(), "WebDAV");
        assert_eq!(backend.id(), "webdav");
        assert!(backend.is_available());
        assert!(backend.unavailable_reason().is_none());
    }

    #[test]
    fn test_backend_config() {
        let backend = WebDavBackend::new()
            .with_port(8080)
            .with_bind_address(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

        assert_eq!(backend.config.port, 8080);
        assert_eq!(
            backend.config.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
        );
    }
}
