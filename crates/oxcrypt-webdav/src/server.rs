//! HTTP server lifecycle management for WebDAV.
//!
//! This module provides the HTTP server that serves WebDAV requests
//! and handles the server lifecycle (start, stop).

use crate::filesystem::CryptomatorWebDav;
use dav_server::{fakels::FakeLs, DavHandler};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// Configuration for the WebDAV server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port to bind to (0 = auto-assign).
    pub port: u16,
    /// Bind address.
    pub bind_address: std::net::IpAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 0, // Auto-assign
            bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        }
    }
}

/// A running WebDAV server instance.
pub struct WebDavServer {
    /// The actual bound address.
    pub addr: SocketAddr,
    /// Shutdown signal sender.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Server task handle.
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl WebDavServer {
    /// Start a new WebDAV server.
    pub async fn start(
        fs: CryptomatorWebDav,
        config: ServerConfig,
    ) -> Result<Self, std::io::Error> {
        let addr = SocketAddr::new(config.bind_address, config.port);
        let listener = TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;

        info!(addr = %actual_addr, "Starting WebDAV server");

        // Build the DAV handler with FakeLs (minimal lock support for macOS/Windows)
        let dav_handler = DavHandler::builder()
            .filesystem(Box::new(fs))
            .locksystem(FakeLs::new())
            .build_handler();

        let dav_handler = Arc::new(dav_handler);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // Spawn the server task
        let server_handle = tokio::spawn(async move {
            tokio::select! {
                () = run_server(listener, dav_handler) => {
                    debug!("Server loop ended");
                }
                _ = shutdown_rx => {
                    info!("Received shutdown signal");
                }
            }
        });

        Ok(Self {
            addr: actual_addr,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        })
    }

    /// Get the URL for this server.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop the server.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_handle.take() {
            let _ = handle.await;
        }
        info!("WebDAV server stopped");
    }

    /// Stop the server synchronously (for use in Drop).
    fn stop_sync(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

impl Drop for WebDavServer {
    fn drop(&mut self) {
        self.stop_sync();
    }
}

/// Run the server accept loop.
async fn run_server(listener: TcpListener, handler: Arc<DavHandler>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let handler = handler.clone();
                        async move {
                            let resp = handler.handle(req).await;
                            Ok::<_, Infallible>(resp)
                        }
                    });

                    if let Err(e) = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                    {
                        // Note: With auto protocol negotiation, we can't easily detect
                        // incomplete messages. Log all connection errors at warn level.
                        warn!(peer = %peer_addr, error = %e, "HTTP connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept connection");
            }
        }
    }
}

/// Timeout for auto-mount operations (15 seconds).
const AUTO_MOUNT_TIMEOUT_SECS: u64 = 15;

/// Attempt to auto-mount via macOS mount_webdav command.
#[cfg(target_os = "macos")]
pub async fn auto_mount_macos(
    url: &str,
    mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    debug!(url = %url, mountpoint = %mountpoint.display(), "Attempting auto-mount on macOS");

    // Create mountpoint if it doesn't exist
    tokio::fs::create_dir_all(mountpoint).await?;

    // Use mount_webdav command with timeout
    // The -S flag suppresses authentication dialogs
    let mount_future = Command::new("mount_webdav")
        .arg("-S") // Suppress authentication dialog
        .arg(url)
        .arg(mountpoint)
        .status();

    let status = match timeout(Duration::from_secs(AUTO_MOUNT_TIMEOUT_SECS), mount_future).await {
        Ok(result) => result?,
        Err(_) => {
            warn!(
                url = %url,
                mountpoint = %mountpoint.display(),
                timeout_secs = AUTO_MOUNT_TIMEOUT_SECS,
                "Auto-mount timed out"
            );
            return Err(std::io::Error::other(format!(
                "mount_webdav timed out after {AUTO_MOUNT_TIMEOUT_SECS}s"
            )));
        }
    };

    if status.success() {
        info!(mountpoint = %mountpoint.display(), "Auto-mount successful");
        Ok(())
    } else {
        warn!(
            status = ?status,
            "Auto-mount failed, user can mount manually via Finder"
        );
        Err(std::io::Error::other("mount_webdav failed"))
    }
}

/// Attempt to unmount a macOS WebDAV mount.
#[cfg(target_os = "macos")]
pub fn unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Unmounting on macOS");

    // Use shared force_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::force_unmount(mountpoint)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Force unmount a macOS WebDAV mount, even if busy.
#[cfg(target_os = "macos")]
pub fn force_unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Force unmounting on macOS");

    // Use shared force_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::force_unmount(mountpoint)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Attempt to unmount on Linux (for manually mounted WebDAV shares).
#[cfg(target_os = "linux")]
pub fn unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Unmounting on Linux");

    // Use shared lazy_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::lazy_unmount(mountpoint)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Force unmount on Linux.
#[cfg(target_os = "linux")]
pub fn force_unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Force unmounting on Linux");

    // Use shared lazy_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::lazy_unmount(mountpoint)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

#[cfg(target_os = "linux")]
pub async fn auto_mount_macos(
    _url: &str,
    _mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    // No auto-mount on Linux - user mounts manually via davfs2 or file manager
    Ok(())
}

/// Attempt to unmount on Windows (for mapped network drives).
#[cfg(target_os = "windows")]
pub fn unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    use std::process::Command;

    debug!(mountpoint = %mountpoint.display(), "Unmounting on Windows");

    // Use net use to disconnect the mapped drive
    let status = Command::new("net")
        .args(["use", "/delete"])
        .arg(mountpoint)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("unmount failed"))
    }
}

/// Force unmount on Windows.
#[cfg(target_os = "windows")]
pub fn force_unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    use std::process::Command;

    debug!(mountpoint = %mountpoint.display(), "Force unmounting on Windows");

    // Use /y to force without prompting
    let status = Command::new("net")
        .args(["use", "/delete", "/y"])
        .arg(mountpoint)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("force unmount failed"))
    }
}

#[cfg(target_os = "windows")]
pub async fn auto_mount_macos(
    _url: &str,
    _mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    // TODO: Could implement auto-mount via `net use` on Windows
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn auto_mount_macos(
    _url: &str,
    _mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn unmount_macos(_mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn force_unmount_macos(_mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 0);
        assert_eq!(
            config.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }
}
