//! File Provider mount backend implementation.
//!
//! This module implements the [`MountBackend`] trait for Apple's File Provider API.

use crate::extension_manager::{ExtensionManager, ExtensionStatus};
use crate::watcher::VaultWatcher;
use crate::xpc::{XpcClient, XpcError};
use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// File Provider mount backend.
///
/// This backend uses Apple's File Provider API to expose vaults
/// as cloud storage volumes in `~/Library/CloudStorage/`.
pub struct FileProviderBackend;

/// Error message for when the File Provider extension needs to be enabled.
const EXTENSION_NOT_ENABLED_MESSAGE: &str = r#"File Provider extension is not enabled.

To enable it:
1. Open System Settings
2. Go to Privacy & Security → Extensions → Added Extensions
3. Find "OxCrypt File Provider" and enable it
4. You may need to restart the app after enabling

The extension must be enabled for the vault to appear in Finder.
"#;

impl FileProviderBackend {
    /// Create a new File Provider backend instance.
    pub fn new() -> Self {
        Self
    }

    /// Check if the host app is available.
    fn is_host_app_available() -> bool {
        XpcClient::connect().is_ok()
    }

    /// Check if the File Provider extension is registered with pluginkit.
    ///
    /// Returns true if the extension appears in the File Provider extension list.
    fn is_extension_registered() -> bool {
        let output = Command::new("pluginkit")
            .args(["-m", "-p", "com.apple.fileprovider-nonui"])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.contains("com.agucova.oxcrypt.fileprovider")
            }
            Err(_) => false,
        }
    }

    /// Wait for the CloudStorage folder to appear after domain registration.
    ///
    /// Returns the path if it appears within the timeout, None otherwise.
    fn wait_for_cloudstorage(display_name: &str, timeout: Duration) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        let cloud_storage = home.join("Library/CloudStorage");

        // macOS transforms the display name to: <BundlePrefix>-<SanitizedDisplayName>
        // e.g., "Large Videos" becomes "OxCryptFileProvider-LargeVideos"
        // The prefix comes from the host app's CFBundleExecutable (OxCryptFileProvider)
        let sanitized_name = display_name.replace(" ", "").replace("(", "").replace(")", "");
        let folder_name = format!("OxCryptFileProvider-{}", sanitized_name);
        let expected_path = cloud_storage.join(&folder_name);

        debug!("Waiting for CloudStorage folder: {:?}", expected_path);

        let start = Instant::now();
        while start.elapsed() < timeout {
            if expected_path.exists() {
                return Some(expected_path.clone());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        None
    }

    fn wait_for_domain_active(
        xpc: &XpcClient,
        domain_id: &str,
        timeout: Duration,
    ) -> Result<bool, XpcError> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            match xpc.get_domain_status(domain_id) {
                Ok(true) => return Ok(true),
                Ok(false) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    fn format_display_name(raw_name: &str) -> String {
        // Just return the raw name - don't add suffix
        raw_name.to_string()
    }

    fn display_name_for_vault(vault_path: &Path) -> String {
        let base = vault_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Vault");
        let base = Self::format_display_name(base);

        let Some(home) = dirs::home_dir() else {
            return base;
        };

        let cloud_storage = home.join("Library/CloudStorage");
        let mut candidate = base.clone();
        let mut suffix = 2;

        loop {
            let path = cloud_storage.join(&candidate);
            if !path.exists() {
                return candidate;
            }
            candidate = format!("{base} ({suffix})");
            suffix += 1;
        }
    }
}

impl Default for FileProviderBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MountBackend for FileProviderBackend {
    fn name(&self) -> &'static str {
        "File Provider"
    }

    fn id(&self) -> &'static str {
        "fileprovider"
    }

    fn is_available(&self) -> bool {
        // Check macOS 13+ and extension availability
        #[cfg(target_os = "macos")]
        {
            // Check if extension is ready or can be installed
            let manager = match ExtensionManager::new() {
                Ok(m) => m,
                Err(_) => return false,
            };

            let status = manager.status();
            matches!(
                status,
                ExtensionStatus::Ready | ExtensionStatus::NeedsInstall | ExtensionStatus::Corrupted
            )
        }
        #[cfg(not(target_os = "macos"))]
        false
    }

    fn unavailable_reason(&self) -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            // Check extension status
            let manager = match ExtensionManager::new() {
                Ok(m) => m,
                Err(e) => {
                    return Some(format!("Failed to initialize extension manager: {e}"));
                }
            };

            match manager.status() {
                ExtensionStatus::NotAvailable => {
                    return Some(
                        "File Provider extension not embedded. Rebuild with extension bundle."
                            .to_string(),
                    );
                }
                ExtensionStatus::Corrupted => {
                    return Some("Extension corrupted. It will be reinstalled on next mount.".to_string());
                }
                _ => {}
            }

            // Check if extension is registered with system
            if !Self::is_extension_registered() {
                return Some(EXTENSION_NOT_ENABLED_MESSAGE.to_string());
            }

            None
        }
        #[cfg(not(target_os = "macos"))]
        Some("File Provider requires macOS 13 (Ventura) or later".to_string())
    }

    fn backend_type(&self) -> BackendType {
        BackendType::FileProvider
    }

    fn description(&self) -> &'static str {
        "Uses Apple File Provider API for cloud storage integration (macOS 13+)"
    }

    fn mount(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        _mountpoint: &Path, // Ignored - File Provider uses fixed location
    ) -> Result<Box<dyn MountHandle>, MountError> {
        info!("Mounting vault via File Provider: {:?}", vault_path);

        // Ensure extension is installed and ready
        let manager = ExtensionManager::new()
            .map_err(|e| MountError::FilesystemCreation(format!("Extension manager error: {e}")))?;

        manager.ensure_ready().map_err(|e| {
            MountError::FilesystemCreation(format!("Failed to prepare extension: {e}"))
        })?;

        info!("Extension ready at: {:?}", manager.extension_path());

        // Connect to XPC service (spawns host app with CLI)
        let xpc = XpcClient::connect().map_err(|e| match e {
            XpcError::HostAppNotFound => MountError::FilesystemCreation(
                "File Provider host app not found. Extension will be installed automatically.".into(),
            ),
            e => MountError::FilesystemCreation(e.to_string()),
        })?;

        let display_name = Self::display_name_for_vault(vault_path);

        // Register domain via XPC (stores password in Keychain)
        let domain_id = xpc
            .register_domain(
                vault_path.to_str().ok_or_else(|| {
                    MountError::FilesystemCreation("vault path is not valid UTF-8".into())
                })?,
                &display_name,
                password,
            )
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        info!("File Provider domain registered: {}", domain_id);

        match Self::wait_for_domain_active(&xpc, &domain_id, Duration::from_secs(5)) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(e) = xpc.unregister_domain(&domain_id) {
                    warn!("Failed to clean up domain after inactive status: {}", e);
                }
                return Err(MountError::FilesystemCreation(
                    "File Provider domain did not become active. \
                     Ensure the host app is running and the extension is enabled."
                        .to_string(),
                ));
            }
            Err(e) => {
                if let Err(e) = xpc.unregister_domain(&domain_id) {
                    warn!("Failed to clean up domain after status error: {}", e);
                }
                return Err(MountError::FilesystemCreation(format!(
                    "Failed to check File Provider domain status: {e}"
                )));
            }
        }

        // Wait for CloudStorage folder to appear (indicates extension is working)
        let mountpoint = match Self::wait_for_cloudstorage(&display_name, Duration::from_secs(10)) {
            Some(path) => {
                info!("File Provider mount appeared at: {:?}", path);
                path
            }
            None => {
                // Check if extension is registered with pluginkit
                if !Self::is_extension_registered() {
                    warn!("File Provider extension not registered with system");
                    // Unregister the domain since it won't work
                    if let Err(e) = xpc.unregister_domain(&domain_id) {
                        warn!("Failed to clean up domain after permission error: {}", e);
                    }
                    return Err(MountError::FilesystemCreation(
                        EXTENSION_NOT_ENABLED_MESSAGE.to_string(),
                    ));
                }

                // Extension is registered but CloudStorage didn't appear
                // This might be a timing issue or the extension crashed
                warn!(
                    "CloudStorage folder did not appear after domain registration. \
                     The extension may need to be enabled in System Settings."
                );

                if let Err(e) = xpc.unregister_domain(&domain_id) {
                    warn!("Failed to clean up domain after mount timeout: {}", e);
                }

                return Err(MountError::FilesystemCreation(
                    "CloudStorage folder did not appear after domain registration. \
                     The extension may be disabled or the domain failed to mount."
                        .to_string(),
                ));
            }
        };

        // Start FSEvents watcher for cloud sync detection
        let watcher = match VaultWatcher::new(vault_path, &domain_id) {
            Ok(mut w) => {
                if let Err(e) = w.start(vault_path) {
                    warn!("Failed to start vault watcher: {}", e);
                }
                Some(w)
            }
            Err(e) => {
                warn!("Failed to create vault watcher: {}", e);
                None
            }
        };

        debug!(
            "File Provider domain registered: {} -> {:?}",
            domain_id, mountpoint
        );

        Ok(Box::new(FileProviderMountHandle {
            domain_id,
            mountpoint,
            vault_path: vault_path.to_path_buf(),
            vault_id: vault_id.to_string(),
            display_name,
            _watcher: watcher,
        }))
    }
}

/// Handle for a mounted File Provider domain.
#[allow(dead_code)]
pub struct FileProviderMountHandle {
    domain_id: String,
    mountpoint: PathBuf,
    vault_path: PathBuf,
    vault_id: String,
    display_name: String,
    _watcher: Option<VaultWatcher>,
}

impl FileProviderMountHandle {
    /// Get the File Provider domain ID for this mount.
    ///
    /// This is the base64-encoded vault path used to identify the domain
    /// with NSFileProviderManager.
    pub fn domain_id(&self) -> &str {
        &self.domain_id
    }

    /// Get the vault path for this mount.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Get the display name for this vault.
    ///
    /// Extracts the vault name from the path.
    pub fn display_name(&self) -> String {
        self.display_name.clone()
    }
}

impl MountHandle for FileProviderMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn unmount(self: Box<Self>) -> Result<(), MountError> {
        info!("Unmounting File Provider domain: {}", self.domain_id);

        // Connect to XPC service and unregister domain
        let xpc = XpcClient::connect().map_err(|e| {
            MountError::FilesystemCreation(format!("Failed to connect to XPC service: {e}"))
        })?;

        xpc.unregister_domain(&self.domain_id)
            .map_err(|e| MountError::UnmountFailed(e.to_string()))?;

        info!("File Provider domain unregistered: {}", self.domain_id);
        Ok(())
    }

    fn force_unmount(self: Box<Self>) -> Result<(), MountError> {
        info!("Force unmounting File Provider domain: {}", self.domain_id);
        // Force unmount uses the same XPC call - the host app handles force removal
        self.unmount()
    }
}
