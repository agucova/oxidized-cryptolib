//! Automatic recovery for FileProvider domains
//!
//! This module handles automatic detection and recovery of disconnected or
//! unhealthy FileProvider domains. It runs periodic health checks and attempts
//! to re-register domains that have become disconnected.

use crate::xpc::XpcClient;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, info, warn};

/// Health status of a FileProvider domain
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainHealth {
    /// Domain is active and responding
    Healthy,
    /// Domain is registered but CloudStorage folder missing
    Disconnected,
    /// Domain is not registered with the system
    Missing,
    /// Unable to determine health status
    Unknown,
}

/// Information about a registered domain for recovery
#[derive(Debug, Clone)]
pub struct DomainInfo {
    /// Domain identifier (base64-encoded vault path)
    pub domain_id: String,
    /// Display name shown in Finder
    pub display_name: String,
    /// Path to the vault
    pub vault_path: PathBuf,
    /// Encrypted password (stored in keychain, this is just the identifier)
    pub password_available: bool,
}

/// Recovery manager for FileProvider domains
pub struct RecoveryManager {
    /// XPC client for domain operations
    client: Arc<XpcClient>,
    /// Registered domains we're monitoring
    domains: Arc<RwLock<HashMap<String, DomainInfo>>>,
    /// Recovery interval (how often to check health)
    check_interval: Duration,
}

impl RecoveryManager {
    /// Create a new recovery manager
    pub fn new(check_interval: Duration) -> Result<Self, crate::xpc::XpcError> {
        let client = Arc::new(XpcClient::connect()?);
        Ok(Self {
            client,
            domains: Arc::new(RwLock::new(HashMap::new())),
            check_interval,
        })
    }

    /// Register a domain for monitoring
    pub async fn monitor_domain(&self, info: DomainInfo) {
        let mut domains = self.domains.write().await;
        domains.insert(info.domain_id.clone(), info);
    }

    /// Stop monitoring a domain
    pub async fn stop_monitoring(&self, domain_id: &str) {
        let mut domains = self.domains.write().await;
        domains.remove(domain_id);
    }

    /// Check the health of a specific domain
    pub async fn check_domain_health(&self, domain_id: &str) -> DomainHealth {
        // Check if domain is registered with the system
        let is_registered = match self.client.get_domain_status(domain_id) {
            Ok(active) => active,
            Err(e) => {
                warn!("Failed to check domain status for {domain_id}: {e}");
                return DomainHealth::Unknown;
            }
        };

        if !is_registered {
            return DomainHealth::Missing;
        }

        // Check if CloudStorage folder exists
        let domains = self.domains.read().await;
        if let Some(info) = domains.get(domain_id) {
            let cloud_storage_exists = Self::check_cloudstorage_exists(&info.display_name);
            if cloud_storage_exists {
                DomainHealth::Healthy
            } else {
                DomainHealth::Disconnected
            }
        } else {
            DomainHealth::Unknown
        }
    }

    /// Check if CloudStorage folder exists for a domain
    fn check_cloudstorage_exists(display_name: &str) -> bool {
        let Some(home) = dirs::home_dir() else {
            return false;
        };
        let cloud_storage = home.join("Library/CloudStorage");

        let path = cloud_storage.join(display_name);
        path.exists()
    }

    /// Attempt to recover a domain
    ///
    /// Returns true if recovery was successful, false otherwise.
    pub async fn recover_domain(&self, domain_id: &str, password: &str) -> bool {
        let domains = self.domains.read().await;
        let Some(info) = domains.get(domain_id) else {
            warn!("Cannot recover unknown domain: {domain_id}");
            return false;
        };

        info!("Attempting to recover domain: {} ({})", info.display_name, domain_id);

        // Try to unregister first (clean up any stale registration)
        if let Err(e) = self.client.unregister_domain(domain_id) {
            debug!("Failed to unregister domain during recovery (may not exist): {e}");
        }

        // Wait a bit for the system to process the unregistration
        time::sleep(Duration::from_millis(500)).await;

        // Re-register the domain
        match self.client.register_domain(
            &info.vault_path.to_string_lossy(),
            &info.display_name,
            password,
        ) {
            Ok(new_domain_id) => {
                if new_domain_id == domain_id {
                    info!("Successfully recovered domain: {}", info.display_name);
                    true
                } else {
                    warn!(
                        "Domain recovered but ID changed: {} -> {}",
                        domain_id, new_domain_id
                    );
                    false
                }
            }
            Err(e) => {
                error!("Failed to recover domain {}: {e}", info.display_name);
                false
            }
        }
    }

    /// Start the recovery task
    ///
    /// This runs in the background and periodically checks domain health,
    /// attempting recovery when issues are detected.
    ///
    /// Note: This method does not automatically recover domains because we don't
    /// have access to the vault password. The recovery must be triggered manually
    /// with the password, or passwords must be retrieved from keychain.
    pub async fn start_recovery_task(self: Arc<Self>) {
        info!(
            "Starting FileProvider recovery task (check interval: {:?})",
            self.check_interval
        );

        let mut interval = time::interval(self.check_interval);

        loop {
            interval.tick().await;

            let domains = self.domains.read().await.clone();
            if domains.is_empty() {
                continue;
            }

            debug!("Running health check for {} domain(s)", domains.len());

            for (domain_id, info) in domains {
                let health = self.check_domain_health(&domain_id).await;

                match health {
                    DomainHealth::Healthy => {
                        debug!("Domain {} is healthy", info.display_name);
                    }
                    DomainHealth::Disconnected => {
                        warn!(
                            "Domain {} is disconnected (CloudStorage folder missing)",
                            info.display_name
                        );
                        // Note: We can't auto-recover without the password
                        // The app will need to prompt the user or retrieve from keychain
                    }
                    DomainHealth::Missing => {
                        warn!("Domain {} is not registered with the system", info.display_name);
                        // Note: We can't auto-recover without the password
                    }
                    DomainHealth::Unknown => {
                        debug!("Unable to determine health for domain {}", info.display_name);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_health_enum() {
        assert_eq!(DomainHealth::Healthy, DomainHealth::Healthy);
        assert_ne!(DomainHealth::Healthy, DomainHealth::Disconnected);
    }

    #[test]
    fn test_domain_info_creation() {
        let info = DomainInfo {
            domain_id: "test123".to_string(),
            display_name: "My Vault".to_string(),
            vault_path: PathBuf::from("/tmp/vault"),
            password_available: true,
        };
        assert_eq!(info.domain_id, "test123");
        assert_eq!(info.display_name, "My Vault");
    }
}
