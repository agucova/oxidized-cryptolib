//! FileProvider domain recovery integration for the desktop app
//!
//! This module integrates the FileProvider recovery manager into the desktop
//! application lifecycle, monitoring mounted domains for disconnection and
//! attempting automatic recovery when possible.

#[cfg(feature = "fileprovider")]
use oxcrypt_fileprovider::recovery::{DomainInfo, DomainHealth, RecoveryManager};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Global FileProvider recovery service instance
static RECOVERY_SERVICE: OnceLock<Arc<FileProviderRecoveryService>> = OnceLock::new();

/// Get the global FileProvider recovery service
///
/// Returns None if FileProvider feature is not enabled or initialization failed.
pub fn recovery_service() -> Option<Arc<FileProviderRecoveryService>> {
    RECOVERY_SERVICE.get().cloned()
}

/// Initialize the global FileProvider recovery service
///
/// This should be called once at app startup. Subsequent calls are ignored.
/// Returns false if already initialized or if initialization failed.
pub fn init_recovery_service() -> bool {
    #[cfg(feature = "fileprovider")]
    {
        if RECOVERY_SERVICE.get().is_some() {
            debug!("FileProvider recovery service already initialized");
            return false;
        }

        match FileProviderRecoveryService::new(Duration::from_secs(60)) {
            Ok(service) => {
                let service = Arc::new(service);
                match start_recovery_task(service.clone()) {
                    Ok(()) => {
                        RECOVERY_SERVICE.set(service).ok();
                        info!("FileProvider recovery service initialized with 60s check interval");
                        true
                    }
                    Err(e) => {
                        warn!("Failed to start FileProvider recovery task: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                warn!("Failed to initialize FileProvider recovery service: {}", e);
                false
            }
        }
    }

    #[cfg(not(feature = "fileprovider"))]
    {
        debug!("FileProvider feature not enabled, skipping recovery service");
        false
    }
}

/// FileProvider domain recovery service
///
/// Monitors registered FileProvider domains for health issues and attempts
/// automatic recovery when domains become disconnected.
#[cfg(feature = "fileprovider")]
pub struct FileProviderRecoveryService {
    manager: Arc<RecoveryManager>,
}

#[cfg(feature = "fileprovider")]
impl FileProviderRecoveryService {
    /// Create a new recovery service
    pub fn new(check_interval: Duration) -> Result<Self, oxcrypt_fileprovider::xpc::XpcError> {
        let manager = Arc::new(RecoveryManager::new(check_interval)?);
        Ok(Self { manager })
    }

    /// Register a mounted FileProvider domain for monitoring
    ///
    /// Call this after successfully mounting a vault via FileProvider.
    pub async fn register_domain(
        &self,
        domain_id: String,
        display_name: String,
        vault_path: PathBuf,
    ) {
        let info = DomainInfo {
            domain_id,
            display_name,
            vault_path,
            password_available: true, // FileProvider stores password in Keychain
        };

        info!("Registering FileProvider domain for monitoring: {}", info.display_name);
        self.manager.monitor_domain(info).await;
    }

    /// Unregister a domain from monitoring
    ///
    /// Call this when a vault is unmounted.
    pub async fn unregister_domain(&self, domain_id: &str) {
        debug!("Unregistering FileProvider domain from monitoring: {}", domain_id);
        self.manager.stop_monitoring(domain_id).await;
    }

    /// Check the health of a specific domain
    pub async fn check_domain_health(&self, domain_id: &str) -> DomainHealth {
        self.manager.check_domain_health(domain_id).await
    }

    /// Attempt to recover a specific domain
    ///
    /// Note: This requires the vault password. For FileProvider domains, the password
    /// is stored in the system Keychain and should be retrieved by the XPC service.
    /// This method is for manual recovery triggers (e.g., user clicks "Reconnect").
    pub async fn recover_domain(&self, domain_id: &str, password: &str) -> bool {
        self.manager.recover_domain(domain_id, password).await
    }

    /// Start the background recovery task
    ///
    /// This runs indefinitely and periodically checks domain health.
    async fn start_recovery_task(&self) {
        self.manager.clone().start_recovery_task().await;
    }
}

#[cfg(feature = "fileprovider")]
fn start_recovery_task(service: Arc<FileProviderRecoveryService>) -> Result<(), String> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            service.start_recovery_task().await;
        });
        return Ok(());
    }

    std::thread::Builder::new()
        .name("fileprovider-recovery".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    error!("Failed to build FileProvider recovery runtime: {}", e);
                    return;
                }
            };

            runtime.block_on(async move {
                service.start_recovery_task().await;
            });
        })
        .map_err(|e| format!("Failed to spawn FileProvider recovery thread: {e}"))?;

    Ok(())
}

// Stub implementation when fileprovider feature is disabled
#[cfg(not(feature = "fileprovider"))]
pub struct FileProviderRecoveryService;

#[cfg(not(feature = "fileprovider"))]
impl FileProviderRecoveryService {
    pub fn new(_check_interval: Duration) -> Result<Self, String> {
        Err("FileProvider feature not enabled".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_service_singleton() {
        // First init should succeed
        let result1 = init_recovery_service();

        // Second init should be no-op (returns false)
        let result2 = init_recovery_service();

        #[cfg(feature = "fileprovider")]
        {
            assert!(result1 || result2); // At least one should work
            assert!(recovery_service().is_some() == result1);
        }

        #[cfg(not(feature = "fileprovider"))]
        {
            assert!(!result1 && !result2);
            assert!(recovery_service().is_none());
        }
    }
}
