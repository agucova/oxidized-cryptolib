//! Extension lifecycle management - installation, verification, and updates

use include_dir::{include_dir, Dir};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

/// Embedded extension bundle (compile-time embedding via include_dir!)
static EXTENSION_BUNDLE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/extension/build/OxCryptFileProvider.app");

/// Compile-time extension hash for integrity verification
const EXTENSION_SHA256: &str = env!("EXTENSION_SHA256");


/// Installation errors
#[derive(Debug, Error)]
pub enum InstallError {
    #[error("Extension bundle not embedded at compile time")]
    NotEmbedded,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Integrity check failed: expected {expected}, got {actual}")]
    IntegrityFailure { expected: String, actual: String },

    #[error("Installation location unavailable: {0}")]
    LocationUnavailable(String),
}

/// Extension installation status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionStatus {
    /// Extension is ready to use
    Ready,
    /// Extension needs installation
    NeedsInstall,
    /// Extension is corrupted and needs reinstallation
    Corrupted,
    /// Extension not available (not embedded)
    NotAvailable,
}

/// Manages FileProvider extension lifecycle
pub struct ExtensionManager {
    install_path: PathBuf,
    install_lock: Mutex<()>,
}

impl ExtensionManager {
    /// Create new extension manager
    pub fn new() -> Result<Self, InstallError> {
        let install_path = Self::default_install_path()?;

        Ok(Self {
            install_path,
            install_lock: Mutex::new(()),
        })
    }

    /// Get default installation path: ~/Library/Application Support/com.oxidized.oxcrypt/FileProvider/
    fn default_install_path() -> Result<PathBuf, InstallError> {
        let app_support = dirs::data_local_dir().ok_or_else(|| {
            InstallError::LocationUnavailable(
                "Could not determine Application Support directory".to_string(),
            )
        })?;

        Ok(app_support
            .join("com.oxidized.oxcrypt")
            .join("FileProvider")
            .join("OxCryptFileProvider.app"))
    }

    /// Check if extension is ready, needs install, or is corrupted
    pub fn status(&self) -> ExtensionStatus {
        // Check if extension was embedded at compile time
        if EXTENSION_SHA256 == "not_built" || EXTENSION_SHA256 == "unknown" {
            return ExtensionStatus::NotAvailable;
        }

        // Check if installed
        if !self.install_path.exists() {
            return ExtensionStatus::NeedsInstall;
        }

        // Verify integrity
        match self.verify_integrity() {
            Ok(()) => ExtensionStatus::Ready,
            Err(_) => ExtensionStatus::Corrupted,
        }
    }

    /// Ensure extension is ready (install if needed)
    pub fn ensure_ready(&self) -> Result<ExtensionStatus, InstallError> {
        let status = self.status();

        match status {
            ExtensionStatus::Ready => Ok(status),
            ExtensionStatus::NeedsInstall | ExtensionStatus::Corrupted => {
                self.install()?;
                Ok(ExtensionStatus::Ready)
            }
            ExtensionStatus::NotAvailable => Err(InstallError::NotEmbedded),
        }
    }

    /// Install extension bundle atomically
    pub fn install(&self) -> Result<(), InstallError> {
        // Acquire lock to prevent concurrent installations
        let _lock = self.install_lock.lock().unwrap();

        // Double-check after acquiring lock
        if self.status() == ExtensionStatus::Ready {
            return Ok(());
        }

        tracing::info!("Installing FileProvider extension to {:?}", self.install_path);

        // Create parent directory
        if let Some(parent) = self.install_path.parent() {
            tracing::info!("Creating parent directory: {:?}", parent);
            fs::create_dir_all(parent).map_err(|e| {
                tracing::error!("Failed to create parent directory {:?}: {}", parent, e);
                e
            })?;
            tracing::info!("Parent directory created successfully");
        }

        // Extract to temporary location first (atomic installation)
        let temp_path = self.install_path.with_extension("app.tmp");
        tracing::info!("Temp install path: {:?}", temp_path);

        if temp_path.exists() {
            tracing::info!("Removing existing temp directory");
            fs::remove_dir_all(&temp_path)?;
        }

        tracing::info!("Starting bundle extraction...");
        self.extract_bundle(&temp_path)?;

        // Remove quarantine attribute on macOS
        #[cfg(target_os = "macos")]
        self.remove_quarantine(&temp_path)?;

        // Atomic rename
        if self.install_path.exists() {
            fs::remove_dir_all(&self.install_path)?;
        }
        fs::rename(&temp_path, &self.install_path)?;

        // Register with Launch Services
        #[cfg(target_os = "macos")]
        self.register_with_launch_services()?;

        tracing::info!("Extension installed successfully");
        Ok(())
    }

    /// Extract embedded bundle to target path
    fn extract_bundle(&self, target: &Path) -> Result<(), InstallError> {
        let entry_count = EXTENSION_BUNDLE.entries().len();
        tracing::debug!("Extension bundle has {} top-level entries", entry_count);

        if entry_count == 0 {
            tracing::error!("Extension bundle is empty - not embedded at compile time!");
            return Err(InstallError::NotEmbedded);
        }

        tracing::debug!("Extracting bundle to {:?}", target);
        extract_dir(&EXTENSION_BUNDLE, target)?;
        tracing::debug!("Bundle extraction complete");
        Ok(())
    }

    /// Verify installed extension integrity
    fn verify_integrity(&self) -> Result<(), InstallError> {
        if !self.install_path.exists() {
            return Err(InstallError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Extension not installed",
            )));
        }

        let actual_hash = compute_directory_hash(&self.install_path)?;

        if actual_hash != EXTENSION_SHA256 {
            return Err(InstallError::IntegrityFailure {
                expected: EXTENSION_SHA256.to_string(),
                actual: actual_hash,
            });
        }

        Ok(())
    }

    /// Remove macOS quarantine attribute
    #[cfg(target_os = "macos")]
    fn remove_quarantine(&self, path: &Path) -> Result<(), InstallError> {
        use std::process::Command;

        let output = Command::new("xattr")
            .arg("-rd")
            .arg("com.apple.quarantine")
            .arg(path)
            .output()?;

        if !output.status.success() {
            tracing::warn!("Failed to remove quarantine attribute (non-fatal)");
        }

        Ok(())
    }

    /// Register extension with Launch Services
    #[cfg(target_os = "macos")]
    fn register_with_launch_services(&self) -> Result<(), InstallError> {
        use std::process::Command;

        let lsregister_path = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";

        let output = Command::new(lsregister_path)
            .arg("-f")
            .arg("-R")
            .arg(&self.install_path)
            .output()?;

        if !output.status.success() {
            tracing::warn!("Failed to register with Launch Services (non-fatal)");
        }

        Ok(())
    }

    /// Get path to installed extension
    pub fn extension_path(&self) -> &Path {
        &self.install_path
    }
}

impl Default for ExtensionManager {
    fn default() -> Self {
        Self::new().expect("Failed to create ExtensionManager")
    }
}

/// Recursively extract embedded directory to filesystem
fn extract_dir(dir: &Dir<'_>, target: &Path) -> Result<(), InstallError> {
    fs::create_dir_all(target)?;

    for entry in dir.entries() {
        // Use only the file name (last component) to avoid path duplication
        let entry_name = entry.path().file_name().ok_or_else(|| {
            InstallError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid entry path: {:?}", entry.path()),
            ))
        })?;
        let target_path = target.join(entry_name);

        if let Some(file) = entry.as_file() {
            // Ensure parent directory exists before creating file
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut output = fs::File::create(&target_path)?;
            output.write_all(file.contents())?;

            // Preserve executable permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(parent) = target_path.parent() {
                    if parent.ends_with("MacOS") {
                        let mut perms = fs::metadata(&target_path)?.permissions();
                        perms.set_mode(0o755);
                        fs::set_permissions(&target_path, perms)?;
                    }
                }
            }
        } else if let Some(subdir) = entry.as_dir() {
            extract_dir(subdir, &target_path)?;
        }
    }

    Ok(())
}

/// Compute SHA256 hash of directory contents
fn compute_directory_hash(dir: &Path) -> Result<String, InstallError> {
    let mut hasher = Sha256::new();
    hash_directory(&mut hasher, dir)?;
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Recursively hash directory contents
fn hash_directory(hasher: &mut Sha256, dir: &Path) -> Result<(), InstallError> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();

        if path.is_dir() {
            hash_directory(hasher, &path)?;
        } else {
            let contents = fs::read(&path)?;
            hasher.update(&contents);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_manager_creation() {
        let manager = ExtensionManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_default_install_path() {
        let path = ExtensionManager::default_install_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.to_string_lossy().contains("Application Support"));
        assert!(path.to_string_lossy().contains("com.oxidized.oxcrypt"));
    }
}
