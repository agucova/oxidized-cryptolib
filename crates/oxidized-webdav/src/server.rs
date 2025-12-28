//! HTTP server lifecycle management for WebDAV.
//!
//! This module provides the HTTP server that serves WebDAV requests
//! and handles the server lifecycle (start, stop).

use crate::filesystem::CryptomatorWebDav;
use dav_server::{fakels::FakeLs, DavHandler};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
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
            .filesystem(fs)
            .locksystem(FakeLs::new())
            .build_handler();

        let dav_handler = Arc::new(dav_handler);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // Spawn the server task
        let server_handle = tokio::spawn(async move {
            tokio::select! {
                _ = run_server(listener, dav_handler) => {
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

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        if !e.is_incomplete_message() {
                            warn!(peer = %peer_addr, error = %e, "HTTP connection error");
                        }
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept connection");
            }
        }
    }
}

/// Attempt to auto-mount via macOS mount_webdav command.
#[cfg(target_os = "macos")]
pub async fn auto_mount_macos(
    url: &str,
    mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    use tokio::process::Command;

    debug!(url = %url, mountpoint = %mountpoint.display(), "Attempting auto-mount on macOS");

    // Create mountpoint if it doesn't exist
    tokio::fs::create_dir_all(mountpoint).await?;

    // Use mount_webdav command
    let status = Command::new("mount_webdav")
        .arg("-S") // Suppress authentication dialog
        .arg(url)
        .arg(mountpoint)
        .status()
        .await?;

    if status.success() {
        info!(mountpoint = %mountpoint.display(), "Auto-mount successful");
        Ok(())
    } else {
        warn!(
            status = ?status,
            "Auto-mount failed, user can mount manually via Finder"
        );
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "mount_webdav failed",
        ))
    }
}

/// Attempt to unmount a macOS WebDAV mount.
#[cfg(target_os = "macos")]
pub fn unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    use std::process::Command;

    debug!(mountpoint = %mountpoint.display(), "Unmounting on macOS");

    // Try umount first
    let status = Command::new("umount").arg(mountpoint).status()?;

    if status.success() {
        return Ok(());
    }

    // Try diskutil unmount as fallback
    let status = Command::new("diskutil")
        .arg("unmount")
        .arg(mountpoint)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unmount failed",
        ))
    }
}

#[cfg(not(target_os = "macos"))]
pub async fn auto_mount_macos(
    _url: &str,
    _mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    // No-op on non-macOS
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn unmount_macos(_mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    // No-op on non-macOS
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
