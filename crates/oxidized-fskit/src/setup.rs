//! FSKitBridge.app setup and detection utilities.
//!
//! This module provides utilities for detecting, downloading, and configuring
//! FSKitBridge.app, which is required for FSKit-based vault mounting on macOS 15.4+.
//!
//! # Detection
//!
//! The [`get_status`] function provides a comprehensive check of FSKitBridge availability:
//!
//! ```ignore
//! use oxidized_fskit::setup::{get_status, BridgeStatus};
//!
//! let status = get_status().await;
//! match status {
//!     BridgeStatus::Ready => println!("FSKitBridge is ready!"),
//!     BridgeStatus::NotInstalled => println!("Please install FSKitBridge.app"),
//!     BridgeStatus::ExtensionDisabled => println!("Enable FSKit extension in System Settings"),
//!     _ => {}
//! }
//! ```
//!
//! # Download (requires `setup` feature)
//!
//! With the `setup` feature enabled, you can download FSKitBridge from GitHub:
//!
//! ```ignore
//! use oxidized_fskit::setup::download_latest;
//!
//! let app_path = download_latest(|progress| {
//!     println!("Downloaded: {:.1}%", progress.fraction * 100.0);
//! }).await?;
//! ```

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// FSKitBridge installation and runtime status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeStatus {
    /// Not running on macOS or macOS version is below 15.4.
    UnsupportedPlatform,
    /// FSKitBridge.app is not installed in any known location.
    NotInstalled,
    /// FSKitBridge.app is installed but has the quarantine attribute.
    Quarantined,
    /// FSKitBridge.app is installed but the extension is not enabled or not responding.
    ExtensionDisabled,
    /// FSKitBridge is fully operational and responding on TCP.
    Ready,
}

impl std::fmt::Display for BridgeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeStatus::UnsupportedPlatform => write!(f, "Unsupported platform"),
            BridgeStatus::NotInstalled => write!(f, "FSKitBridge.app not installed"),
            BridgeStatus::Quarantined => write!(f, "FSKitBridge.app is quarantined"),
            BridgeStatus::ExtensionDisabled => write!(f, "FSKit extension not enabled"),
            BridgeStatus::Ready => write!(f, "Ready"),
        }
    }
}

/// Known FSKitBridge.app installation paths.
pub const BRIDGE_PATHS: &[&str] = &[
    "/Applications/FSKitBridge.app",
    "~/Applications/FSKitBridge.app",
];

/// TCP port that FSKitBridge listens on.
pub const BRIDGE_PORT: u16 = 35367;

/// GitHub releases URL for FSKitBridge.
pub const RELEASES_URL: &str = "https://github.com/debox-network/FSKitBridge/releases";

/// GitHub API URL for latest release.
pub const RELEASES_API_URL: &str =
    "https://api.github.com/repos/debox-network/FSKitBridge/releases/latest";

/// Minimum macOS version required for FSKit (15.4).
const MIN_MACOS_MAJOR: u32 = 15;
const MIN_MACOS_MINOR: u32 = 4;

/// Check if the current macOS version supports FSKit.
#[cfg(target_os = "macos")]
pub fn check_macos_version() -> bool {
    use std::process::Command;

    if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output()
        && let Ok(version) = String::from_utf8(output.stdout) {
            let parts: Vec<&str> = version.trim().split('.').collect();
            if parts.len() >= 2
                && let (Ok(major), Ok(minor)) =
                    (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                {
                    return major > MIN_MACOS_MAJOR
                        || (major == MIN_MACOS_MAJOR && minor >= MIN_MACOS_MINOR);
                }
        }
    false
}

#[cfg(not(target_os = "macos"))]
pub fn check_macos_version() -> bool {
    false
}

/// Find FSKitBridge.app installation path.
///
/// Checks known installation locations and returns the first one found.
pub fn find_installation() -> Option<PathBuf> {
    for path_str in BRIDGE_PATHS {
        let expanded = if path_str.starts_with('~') {
            if let Some(home) = dirs::home_dir() {
                home.join(&path_str[2..])
            } else {
                continue;
            }
        } else {
            PathBuf::from(path_str)
        };

        if expanded.exists() && expanded.is_dir() {
            return Some(expanded);
        }
    }
    None
}

/// Check if an app bundle has the quarantine extended attribute.
#[cfg(target_os = "macos")]
pub fn is_quarantined(app_path: &Path) -> bool {
    use std::process::Command;

    Command::new("xattr")
        .args(["-p", "com.apple.quarantine"])
        .arg(app_path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
pub fn is_quarantined(_app_path: &Path) -> bool {
    false
}

/// Remove the quarantine extended attribute from an app bundle.
#[cfg(target_os = "macos")]
pub fn remove_quarantine(app_path: &Path) -> io::Result<()> {
    use std::process::Command;

    let status = Command::new("xattr")
        .args(["-cr"])
        .arg(app_path)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "Failed to remove quarantine attribute",
        ))
    }
}

#[cfg(not(target_os = "macos"))]
pub fn remove_quarantine(_app_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Check if FSKitBridge is responding on TCP.
///
/// This verifies that the FSKit extension is enabled and FSKitBridge.app is running.
pub async fn check_bridge_connection() -> bool {
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(("127.0.0.1", BRIDGE_PORT)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// Synchronous version of bridge connection check.
pub fn check_bridge_connection_sync() -> bool {
    use std::net::TcpStream;

    TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], BRIDGE_PORT)),
        Duration::from_secs(2),
    )
    .is_ok()
}

/// Get comprehensive FSKitBridge status.
///
/// Performs all checks in order:
/// 1. Platform/version check
/// 2. Installation check
/// 3. Quarantine check
/// 4. TCP connection check
pub async fn get_status() -> BridgeStatus {
    // Check platform first
    if !check_macos_version() {
        return BridgeStatus::UnsupportedPlatform;
    }

    // Check if installed
    let app_path = match find_installation() {
        Some(p) => p,
        None => return BridgeStatus::NotInstalled,
    };

    // Check quarantine
    if is_quarantined(&app_path) {
        return BridgeStatus::Quarantined;
    }

    // Check TCP connection
    if check_bridge_connection().await {
        BridgeStatus::Ready
    } else {
        BridgeStatus::ExtensionDisabled
    }
}

/// Synchronous version of status check.
pub fn get_status_sync() -> BridgeStatus {
    // Check platform first
    if !check_macos_version() {
        return BridgeStatus::UnsupportedPlatform;
    }

    // Check if installed
    let app_path = match find_installation() {
        Some(p) => p,
        None => return BridgeStatus::NotInstalled,
    };

    // Check quarantine
    if is_quarantined(&app_path) {
        return BridgeStatus::Quarantined;
    }

    // Check TCP connection
    if check_bridge_connection_sync() {
        BridgeStatus::Ready
    } else {
        BridgeStatus::ExtensionDisabled
    }
}

/// Open System Settings to the File System Extensions pane.
#[cfg(target_os = "macos")]
pub fn open_system_settings_extensions() -> io::Result<()> {
    use std::process::Command;

    // Deep link to Login Items & Extensions settings
    let status = Command::new("open")
        .arg("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "Failed to open System Settings",
        ))
    }
}

#[cfg(not(target_os = "macos"))]
pub fn open_system_settings_extensions() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "System Settings is only available on macOS",
    ))
}

/// Launch FSKitBridge.app to register the extension.
#[cfg(target_os = "macos")]
pub fn launch_bridge() -> io::Result<PathBuf> {
    use std::process::Command;

    let app_path = find_installation().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "FSKitBridge.app not found")
    })?;

    let status = Command::new("open").arg("-a").arg(&app_path).status()?;

    if status.success() {
        Ok(app_path)
    } else {
        Err(io::Error::other(
            "Failed to launch FSKitBridge.app",
        ))
    }
}

#[cfg(not(target_os = "macos"))]
pub fn launch_bridge() -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "FSKitBridge is only available on macOS",
    ))
}

// ============================================================================
// Download functionality (feature-gated)
// ============================================================================

/// Download progress information.
#[cfg(feature = "setup")]
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Fraction complete (0.0 to 1.0).
    pub fraction: f32,
    /// Bytes downloaded so far.
    pub bytes_downloaded: u64,
    /// Total bytes to download (if known).
    pub total_bytes: Option<u64>,
}

/// Errors that can occur during setup/download.
#[cfg(feature = "setup")]
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP extraction error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("No suitable asset found in release")]
    NoAssetFound,

    #[error("FSKitBridge.app not found in archive")]
    AppNotFoundInArchive,

    #[error("Failed to parse GitHub API response: {0}")]
    ParseError(String),
}

#[cfg(feature = "setup")]
mod download {
    use super::*;
    use std::io::Write;

    /// GitHub API response for a release.
    #[derive(Debug, serde::Deserialize)]
    struct GitHubRelease {
        tag_name: String,
        assets: Vec<GitHubAsset>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct GitHubAsset {
        name: String,
        browser_download_url: String,
        size: u64,
    }

    /// Download the latest FSKitBridge.app from GitHub releases.
    ///
    /// Downloads to a temporary directory and returns the path to the extracted .app bundle.
    /// The caller is responsible for moving it to the final destination.
    pub async fn download_latest<F>(on_progress: F) -> Result<PathBuf, SetupError>
    where
        F: Fn(DownloadProgress) + Send + 'static,
    {
        let client = reqwest::Client::builder()
            .user_agent("oxidized-cryptolib")
            .build()?;

        // Fetch latest release info
        let release: GitHubRelease = client
            .get(RELEASES_API_URL)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        tracing::info!("Found FSKitBridge release: {}", release.tag_name);

        // Find the ZIP asset
        let asset = release
            .assets
            .iter()
            .find(|a| a.name.ends_with(".zip") || a.name.contains("FSKitBridge"))
            .ok_or(SetupError::NoAssetFound)?;

        tracing::info!("Downloading {} ({} bytes)", asset.name, asset.size);

        // Create temp directory
        let temp_dir = tempfile::tempdir()?;
        let zip_path = temp_dir.path().join(&asset.name);

        // Download with progress
        let mut response = client
            .get(&asset.browser_download_url)
            .send()
            .await?
            .error_for_status()?;

        let total_bytes = asset.size;
        let mut downloaded: u64 = 0;
        let mut file = std::fs::File::create(&zip_path)?;

        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk)?;
            downloaded += chunk.len() as u64;
            on_progress(DownloadProgress {
                fraction: downloaded as f32 / total_bytes as f32,
                bytes_downloaded: downloaded,
                total_bytes: Some(total_bytes),
            });
        }

        file.flush()?;
        drop(file);

        tracing::info!("Download complete, extracting...");

        // Extract ZIP
        let zip_file = std::fs::File::open(&zip_path)?;
        let mut archive = zip::ZipArchive::new(zip_file)?;
        archive.extract(temp_dir.path())?;

        // Find the .app bundle
        let app_path = find_app_in_dir(temp_dir.path())?;

        // Move to a persistent temp location (tempdir would delete on drop)
        let persistent_temp = std::env::temp_dir().join("FSKitBridge.app");
        if persistent_temp.exists() {
            std::fs::remove_dir_all(&persistent_temp)?;
        }
        copy_dir_all(&app_path, &persistent_temp)?;

        Ok(persistent_temp)
    }

    /// Find .app bundle in a directory.
    fn find_app_in_dir(dir: &Path) -> Result<PathBuf, SetupError> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".app"))
                    .unwrap_or(false)
                {
                    return Ok(path);
                }
                // Check subdirectories
                if let Ok(found) = find_app_in_dir(&path) {
                    return Ok(found);
                }
            }
        }
        Err(SetupError::AppNotFoundInArchive)
    }

    /// Recursively copy a directory.
    fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if ty.is_dir() {
                copy_dir_all(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }

    /// Install FSKitBridge.app to a destination directory.
    ///
    /// Copies the app bundle and removes the quarantine attribute.
    pub async fn install_to(app_path: &Path, dest_dir: &Path) -> Result<PathBuf, SetupError> {
        let dest_app = dest_dir.join("FSKitBridge.app");

        // Remove existing installation
        if dest_app.exists() {
            std::fs::remove_dir_all(&dest_app)?;
        }

        // Copy app bundle
        copy_dir_all(app_path, &dest_app)?;

        // Remove quarantine
        #[cfg(target_os = "macos")]
        {
            let _ = remove_quarantine(&dest_app);
        }

        Ok(dest_app)
    }
}

#[cfg(feature = "setup")]
pub use download::{download_latest, install_to};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_status_display() {
        assert_eq!(BridgeStatus::Ready.to_string(), "Ready");
        assert_eq!(
            BridgeStatus::NotInstalled.to_string(),
            "FSKitBridge.app not installed"
        );
    }

    #[test]
    fn test_find_installation_returns_none_when_not_installed() {
        // This test assumes FSKitBridge is not installed in the test environment
        // It's mainly a smoke test to ensure the function doesn't panic
        let _ = find_installation();
    }

    #[test]
    fn test_check_macos_version_doesnt_panic() {
        let _ = check_macos_version();
    }

    #[test]
    fn test_check_bridge_connection_sync() {
        // This should return false if FSKitBridge isn't running
        // Just a smoke test to ensure it doesn't hang forever
        let result = check_bridge_connection_sync();
        // We don't assert the result since it depends on the environment
        let _ = result;
    }

    #[test]
    fn test_get_status_sync() {
        let status = get_status_sync();
        // On non-macOS or without FSKitBridge, this should not be Ready
        // Just verify it doesn't panic
        println!("FSKitBridge status: {:?}", status);
    }
}
