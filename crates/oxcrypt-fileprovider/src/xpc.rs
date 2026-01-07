//! XPC client for communicating with the File Provider host app.
//!
//! This module provides a Rust client that communicates with the File Provider
//! host application via CLI commands for domain management and NSXPCConnection
//! for secure password retrieval from Keychain.
//!
//! ## Architecture
//!
//! The host app runs in one of three modes:
//! - **CLI mode**: Process a single command (register, list, etc.) and exit
//! - **Daemon mode**: Run as background service with XPC listeners (`--daemon`)
//! - **GUI mode**: Show management window (for debugging)
//!
//! CLI commands work without the daemon running. The XPC password service
//! requires the daemon to be running with Mach XPC listeners active.

use crate::extension_manager::ExtensionManager;
use crate::ffi::XPCPasswordClient;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

/// XPC client error type.
#[derive(Debug, Error)]
pub enum XpcError {
    /// Connection failed
    #[error("failed to connect to File Provider host app: {0}")]
    ConnectionFailed(String),

    /// Service returned an error
    #[error("File Provider error: {0}")]
    ServiceError(String),

    /// Host app not found
    #[error("File Provider host app not found at expected location")]
    HostAppNotFound,

    /// Invalid response
    #[error("invalid response from host app: {0}")]
    InvalidResponse(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Password not found in Keychain for the specified domain
    #[error("password not found in Keychain for domain: {0}")]
    PasswordNotFound(String),

    /// Keychain is locked and needs to be unlocked
    #[error("Keychain is locked. Please unlock and try again")]
    KeychainLocked,

    /// Keychain access denied (check code signing and access groups)
    #[error("Keychain access denied. Check code signing and access groups")]
    KeychainAccessDenied,

    /// Invalid domain identifier format
    #[error("Invalid domain identifier")]
    InvalidDomainId,

    /// Rate limit exceeded (too many password requests)
    #[error("Rate limit exceeded. Too many password requests in a short time")]
    RateLimitExceeded,
}

/// XPC client for the File Provider host app.
///
/// This client spawns the host app with CLI commands to perform operations.
pub struct XpcClient {
    host_app_path: PathBuf,
}

impl XpcClient {
    /// Find the File Provider host app.
    fn find_host_app() -> Option<PathBuf> {
        // Single source of truth: embedded bundle installed by ExtensionManager.
        if let Ok(manager) = ExtensionManager::new() {
            let installed_path = manager
                .extension_path()
                .join("Contents/MacOS/OxCryptFileProvider");
            if installed_path.exists() {
                debug!("Found host app at embedded location: {:?}", installed_path);
                return Some(installed_path);
            }
        }

        None
    }

    /// Connect to the File Provider XPC service.
    ///
    /// This finds the host app and prepares to spawn it for commands.
    pub fn connect() -> Result<Self, XpcError> {
        debug!("Looking for File Provider host app");

        let host_app_path = Self::find_host_app()
            .ok_or(XpcError::HostAppNotFound)?;

        info!("Using File Provider host app: {:?}", host_app_path);

        Ok(Self { host_app_path })
    }

    /// Run a command on the host app and return stdout.
    fn run_command(&self, args: &[&str], env: Option<(&str, &str)>) -> Result<String, XpcError> {
        debug!("Running host app command: {:?}", args);

        let mut cmd = Command::new(&self.host_app_path);
        cmd.args(args);

        if let Some((key, value)) = env {
            cmd.env(key, value);
        }

        let output = cmd.output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            debug!("Command output: {}", stdout.trim());
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            warn!("Command failed: {}", stderr.trim());
            Err(XpcError::ServiceError(stderr.trim().to_string()))
        }
    }

    /// Register a vault as a File Provider domain.
    ///
    /// Returns the domain identifier on success.
    pub fn register_domain(
        &self,
        vault_path: &str,
        display_name: &str,
        password: &str,
    ) -> Result<String, XpcError> {
        info!("Registering File Provider domain: {}", display_name);

        let output = self.run_command(
            &["register", "--vault", vault_path, "--name", display_name],
            Some(("OXCRYPT_PASSWORD", password)),
        )?;

        // Parse "OK:<domain_id>" response
        let trimmed = output.trim();
        if let Some(domain_id) = trimmed.strip_prefix("OK:") {
            Ok(domain_id.to_string())
        } else if trimmed == "OK" {
            // Generate domain ID ourselves if not returned
            let domain_id = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                vault_path.as_bytes(),
            );
            Ok(domain_id)
        } else {
            Err(XpcError::InvalidResponse(output))
        }
    }

    /// Unregister a File Provider domain.
    pub fn unregister_domain(&self, domain_id: &str) -> Result<(), XpcError> {
        info!("Unregistering File Provider domain: {}", domain_id);

        let output = self.run_command(&["unregister", "--domain", domain_id], None)?;

        if output.trim() == "OK" {
            Ok(())
        } else {
            Err(XpcError::InvalidResponse(output))
        }
    }

    /// Signal the working set enumerator to refresh.
    pub fn signal_changes(&self, _domain_id: &str) -> Result<(), XpcError> {
        // Signal changes is not exposed via CLI yet
        // This would require the XPC service to be running
        debug!("Signal changes not implemented via CLI");
        Ok(())
    }

    /// List all registered domains.
    ///
    /// Returns a list of (identifier, display_name) tuples.
    pub fn list_domains(&self) -> Result<Vec<(String, String)>, XpcError> {
        debug!("Listing File Provider domains");

        let output = self.run_command(&["list"], None)?;

        let mut domains = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed == "No domains registered" {
                continue;
            }
            // Parse "identifier\tdisplay_name" format
            if let Some((id, name)) = trimmed.split_once('\t') {
                domains.push((id.to_string(), name.to_string()));
            }
        }

        Ok(domains)
    }

    /// Get the status of a domain.
    pub fn get_domain_status(&self, domain_id: &str) -> Result<bool, XpcError> {
        debug!("Getting status for domain: {}", domain_id);

        let output = self.run_command(&["status", "--domain", domain_id], None)?;

        Ok(output.trim() == "ACTIVE")
    }

    /// Get the path to the host app executable.
    pub fn host_app_path(&self) -> &PathBuf {
        &self.host_app_path
    }

    /// Check if the File Provider daemon is running.
    ///
    /// The daemon must be running for XPC services (like password retrieval) to work.
    /// CLI commands work without the daemon.
    pub fn is_daemon_running(&self) -> bool {
        // Check for running process by looking for our Mach service
        // We use pgrep to find the process by path
        let output = Command::new("pgrep")
            .args(["-f", "OxCryptFileProvider.*--daemon"])
            .output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Start the File Provider daemon in background mode.
    ///
    /// The daemon provides XPC services for password retrieval and domain signaling.
    /// It runs without a GUI and stays alive until terminated.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the daemon was started successfully or was already running.
    pub fn start_daemon(&self) -> Result<(), XpcError> {
        if self.is_daemon_running() {
            debug!("File Provider daemon already running");
            return Ok(());
        }

        info!("Starting File Provider daemon: {:?} --daemon", self.host_app_path);

        // Spawn the daemon in background (detached from this process)
        let child = Command::new(&self.host_app_path)
            .arg("--daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        match child {
            Ok(_) => {
                // Wait a bit for the daemon to initialize XPC listeners
                std::thread::sleep(Duration::from_millis(500));

                if self.is_daemon_running() {
                    info!("File Provider daemon started successfully");
                    Ok(())
                } else {
                    warn!("Daemon process started but not detected as running");
                    // Still return Ok since the process was spawned
                    Ok(())
                }
            }
            Err(e) => {
                warn!("Failed to start File Provider daemon: {}", e);
                Err(XpcError::ConnectionFailed(format!(
                    "Failed to start daemon: {e}"
                )))
            }
        }
    }

    /// Ensure the daemon is running, starting it if necessary.
    ///
    /// This should be called before using XPC services that require the daemon.
    pub fn ensure_daemon_running(&self) -> Result<(), XpcError> {
        if self.is_daemon_running() {
            return Ok(());
        }
        self.start_daemon()
    }

    /// Retrieve password for a domain from Keychain via secure XPC.
    ///
    /// This method connects to the password retrieval XPC service and requests
    /// the password for the specified domain. The XPC service validates the caller's
    /// code signature using audit tokens before returning the password.
    ///
    /// **Note**: This method requires the File Provider daemon to be running.
    /// It will automatically start the daemon if not already running.
    ///
    /// # Security
    ///
    /// - Uses NSXPCConnection with audit token verification (immune to PID reuse)
    /// - Mach port isolation prevents stdout interception
    /// - Only apps with Team ID 2LR4AGRZW3 + required entitlements can access
    ///
    /// # Arguments
    ///
    /// * `domain_id` - Base64url-encoded vault path (domain identifier)
    ///
    /// # Returns
    ///
    /// The password string if found, or an error if not found or access denied.
    ///
    /// # Errors
    ///
    /// - `PasswordNotFound` - Password not in Keychain for this domain
    /// - `KeychainLocked` - Keychain needs to be unlocked first
    /// - `KeychainAccessDenied` - Code signing or access group mismatch
    /// - `InvalidDomainId` - Domain ID format invalid
    /// - `RateLimitExceeded` - Too many requests (>10/min)
    /// - `ConnectionFailed` - Could not connect to XPC service or start daemon
    pub fn get_password(&self, domain_id: &str) -> Result<String, XpcError> {
        debug!("Retrieving password for domain: {}", domain_id);

        // Ensure daemon is running (XPC service requires it)
        self.ensure_daemon_running()?;

        // Create XPC client and connect
        let client = XPCPasswordClient::new();
        client.connect();

        // Request password via XPC (synchronous call)
        let response = client.get_password(domain_id.to_string());

        // Parse response: "OK:<password>" or "ERROR:<code>:<message>"
        if let Some(password) = response.strip_prefix("OK:") {
            info!("Password retrieved successfully for domain");
            Ok(password.to_string())
        } else if let Some(error_part) = response.strip_prefix("ERROR:") {
            // Parse "CODE:message" format
            let parts: Vec<&str> = error_part.splitn(2, ':').collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[0].parse::<i32>() {
                    let error = match code {
                        1 => XpcError::PasswordNotFound(domain_id.to_string()),
                        2 => XpcError::KeychainLocked,
                        3 => XpcError::KeychainAccessDenied,
                        4 => XpcError::InvalidDomainId,
                        5 => XpcError::RateLimitExceeded,
                        _ => XpcError::ServiceError(parts[1].to_string()),
                    };
                    warn!("Password retrieval failed: {}", error);
                    return Err(error);
                }
            }
            // Fallback if parsing fails
            warn!("Password retrieval failed: {}", error_part);
            Err(XpcError::ServiceError(error_part.to_string()))
        } else {
            warn!("Invalid response format from XPC service: {}", response);
            Err(XpcError::InvalidResponse(response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_host_app() {
        // This test just verifies the find logic doesn't panic
        let _ = XpcClient::find_host_app();
    }
}
