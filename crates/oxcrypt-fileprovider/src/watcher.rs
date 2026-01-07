//! FSEvents watcher for detecting vault changes.
//!
//! When a vault is stored on a cloud service (Google Drive, Dropbox, etc.),
//! this watcher detects changes to the encrypted files and signals the
//! File Provider extension to refresh its working set.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::xpc::XpcClient;

/// Error type for watcher operations.
#[derive(Debug, Error)]
pub enum WatchError {
    /// Failed to create watcher
    #[error("failed to create watcher: {0}")]
    WatcherError(#[from] notify::Error),

    /// Failed to connect to XPC service
    #[error("failed to connect to XPC service: {0}")]
    XpcError(#[from] crate::xpc::XpcError),
}

/// FSEvents watcher for vault changes.
///
/// This watcher monitors the vault directory for changes and signals
/// the File Provider extension when the working set needs to be refreshed.
pub struct VaultWatcher {
    watcher: RecommendedWatcher,
    domain_id: String,
}

impl VaultWatcher {
    /// Create a new watcher for the given vault.
    ///
    /// The watcher will signal the File Provider extension via XPC when
    /// changes are detected in the vault's `/d/` directory.
    pub fn new(vault_path: &Path, domain_id: &str) -> Result<Self, WatchError> {
        info!("Starting vault watcher for: {:?}", vault_path);

        let domain_id_clone = domain_id.to_string();
        let (tx, rx) = mpsc::channel();

        // Create watcher with debounced events
        let watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
            if let Ok(event) = res {
                // Only care about changes in the vault's d/ directory
                let is_vault_change = event.paths.iter().any(|p| {
                    p.to_str().is_some_and(|s| s.contains("/d/"))
                });

                if is_vault_change {
                    debug!("Vault change detected: {:?}", event.paths);
                    let _ = tx.send(());
                }
            }
        })?;

        // Start debounce thread
        let domain_id_debounce = domain_id.to_string();
        std::thread::spawn(move || {
            let mut last_signal = Instant::now();
            let debounce_duration = Duration::from_millis(500);

            while let Ok(()) = rx.recv() {
                let now = Instant::now();
                if now.duration_since(last_signal) > debounce_duration {
                    debug!("Signaling File Provider for domain: {}", domain_id_debounce);

                    // Try to connect and signal
                    match XpcClient::connect() {
                        Ok(client) => {
                            if let Err(e) = client.signal_changes(&domain_id_debounce) {
                                warn!("Failed to signal changes: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to connect to XPC service: {}", e);
                        }
                    }

                    last_signal = now;
                }
            }

            info!("Vault watcher thread exiting");
        });

        Ok(Self {
            watcher,
            domain_id: domain_id_clone,
        })
    }

    /// Start watching the vault directory.
    pub fn start(&mut self, vault_path: &Path) -> Result<(), WatchError> {
        self.watcher.watch(vault_path, RecursiveMode::Recursive)?;
        info!("Watching vault: {:?}", vault_path);
        Ok(())
    }

    /// Stop watching the vault directory.
    pub fn stop(&mut self, vault_path: &Path) -> Result<(), WatchError> {
        self.watcher.unwatch(vault_path)?;
        info!("Stopped watching vault: {:?}", vault_path);
        Ok(())
    }

    /// Get the domain ID this watcher is associated with.
    pub fn domain_id(&self) -> &str {
        &self.domain_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    #[ignore = "Requires XPC service to be running"]
    fn test_watcher_creation() {
        let temp = tempdir().unwrap();
        let vault_path = temp.path();

        // Create d/ directory structure
        fs::create_dir_all(vault_path.join("d/AB")).unwrap();

        let watcher = VaultWatcher::new(vault_path, "test-domain");
        assert!(watcher.is_ok());
    }
}
