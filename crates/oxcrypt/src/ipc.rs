//! IPC for CLI-to-daemon communication.
//!
//! Uses Unix domain sockets to communicate with running mount daemons.
//! Each mount daemon listens on a socket for stats requests.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use oxcrypt_mount::stats::VaultStatsSnapshot;

/// IPC request types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum IpcRequest {
    /// Request current stats snapshot
    #[serde(rename = "get_stats")]
    GetStats,
    /// Ping to check if daemon is alive
    #[serde(rename = "ping")]
    Ping,
}

/// IPC response types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcResponse {
    #[serde(rename = "stats")]
    Stats { data: VaultStatsSnapshot },
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "error")]
    Error { message: String },
}

/// Get the socket directory path.
///
/// Uses a short path under /tmp to avoid exceeding Unix socket path limits
/// (104 chars on macOS). The directory is per-user for security.
pub fn socket_dir() -> Result<PathBuf> {
    // Unix sockets have a ~104 character path limit on macOS.
    // Using /tmp/oxcrypt-{uid}/ keeps paths short while being per-user.
    #[cfg(unix)]
    let socket_dir = {
        let uid = nix::unistd::getuid();
        PathBuf::from(format!("/tmp/oxcrypt-{}", uid))
    };

    #[cfg(not(unix))]
    let socket_dir = {
        let dirs = directories::ProjectDirs::from("com", "oxcrypt", "oxcrypt")
            .context("Failed to determine config directory")?;
        dirs.config_dir().join("sockets")
    };

    std::fs::create_dir_all(&socket_dir)?;

    // Secure the directory (only owner can access)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&socket_dir, perms)?;
    }

    Ok(socket_dir)
}

/// Generate socket path for a mount.
pub fn socket_path_for_mount(mount_id: &str) -> Result<PathBuf> {
    Ok(socket_dir()?.join(format!("{}.sock", mount_id)))
}

// === Client Functions ===

/// Connect to a daemon's IPC socket and request stats.
#[cfg(unix)]
pub fn get_stats(socket_path: &Path) -> Result<VaultStatsSnapshot> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to {}", socket_path.display()))?;

    // Set timeout
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    // Send request
    let request = IpcRequest::GetStats;
    let mut request_json = serde_json::to_string(&request)?;
    request_json.push('\n');
    stream.write_all(request_json.as_bytes())?;
    stream.flush()?;

    // Read response
    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    let response: IpcResponse =
        serde_json::from_str(&response_line).context("Failed to parse IPC response")?;

    match response {
        IpcResponse::Stats { data } => Ok(data),
        IpcResponse::Error { message } => anyhow::bail!("Daemon error: {}", message),
        _ => anyhow::bail!("Unexpected response type"),
    }
}

/// Check if daemon is alive.
#[cfg(unix)]
pub fn ping(socket_path: &Path) -> Result<bool> {
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;

    let request = IpcRequest::Ping;
    let mut request_json = serde_json::to_string(&request)?;
    request_json.push('\n');
    stream.write_all(request_json.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    if reader.read_line(&mut response_line).is_err() {
        return Ok(false);
    }

    Ok(matches!(
        serde_json::from_str::<IpcResponse>(&response_line),
        Ok(IpcResponse::Pong)
    ))
}

// === Server Functions ===

use oxcrypt_mount::VaultStats;
use std::sync::Arc;

/// Handle an IPC request and return a response.
///
/// This is the core request handler called by the mount daemon's main loop.
pub fn handle_request(request: IpcRequest, stats: &Arc<VaultStats>) -> IpcResponse {
    match request {
        IpcRequest::GetStats => {
            let snapshot = stats.snapshot();
            IpcResponse::Stats { data: snapshot }
        }
        IpcRequest::Ping => IpcResponse::Pong,
    }
}

/// IPC server for a mount daemon.
#[cfg(unix)]
pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

#[cfg(unix)]
impl IpcServer {
    /// Create a new IPC server at the given socket path.
    pub fn new(socket_path: PathBuf) -> Result<Self> {
        // Remove existing socket if present
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;

        // Set non-blocking for accept loop
        listener.set_nonblocking(true)?;

        Ok(Self {
            listener,
            socket_path,
        })
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Handle a single incoming connection.
    /// Returns None if no connection is pending (non-blocking).
    pub fn try_accept<F>(&self, handler: F) -> Result<Option<()>>
    where
        F: FnOnce(IpcRequest) -> IpcResponse,
    {
        match self.listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

                let mut reader = BufReader::new(&stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line)?;

                let request: IpcRequest =
                    serde_json::from_str(&request_line).unwrap_or_else(|e| {
                        tracing::warn!("Invalid IPC request: {}", e);
                        IpcRequest::Ping // Default to ping for invalid requests
                    });

                let response = handler(request);
                let mut response_json = serde_json::to_string(&response)?;
                response_json.push('\n');

                // Drop the reader to release the borrow on stream
                let _ = reader.into_inner();
                stream.write_all(response_json.as_bytes())?;
                stream.flush()?;

                Ok(Some(()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(unix)]
impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
