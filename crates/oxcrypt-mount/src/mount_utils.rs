//! Mount point utilities for detecting stale mounts and finding available paths.
//!
//! When a FUSE daemon crashes without proper cleanup, the mount becomes "stale" -
//! any filesystem operation on it blocks indefinitely. This module provides
//! utilities to detect such situations and find alternative mount points.
//!
//! # Non-blocking Design
//!
//! The primary functions in this module use the system mount table for detection,
//! which never blocks on ghost mounts. Functions that probe the filesystem directly
//! are deprecated as they can leak threads.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::mount_markers::{get_system_mounts_detailed, SystemMount};

/// Default timeout for filesystem accessibility checks (deprecated functions only)
pub const DEFAULT_ACCESS_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum suffix number to try when finding alternative mount points
const MAX_SUFFIX: u32 = 99;

/// Normalize a path for mount comparison without touching the filesystem.
///
/// This avoids the `canonicalize()` syscall which can block indefinitely on ghost mounts.
/// For mount comparison purposes, we only need to handle:
/// 1. Trailing slashes
/// 2. Known symlink mappings (e.g., `/tmp` -> `/private/tmp` on macOS)
///
/// # Example
///
/// ```
/// use std::path::Path;
/// use oxcrypt_mount::normalize_mount_path;
///
/// // On macOS, /tmp is a symlink to /private/tmp
/// #[cfg(target_os = "macos")]
/// assert_eq!(
///     normalize_mount_path(Path::new("/tmp/myvault")),
///     Path::new("/private/tmp/myvault")
/// );
///
/// // Trailing slashes are removed
/// assert_eq!(
///     normalize_mount_path(Path::new("/mnt/vault/")),
///     Path::new("/mnt/vault")
/// );
/// ```
pub fn normalize_mount_path(path: &Path) -> PathBuf {
    let mut path_str = path.to_string_lossy().into_owned();

    // Remove trailing slash (except for root)
    if path_str.len() > 1 && path_str.ends_with('/') {
        path_str.pop();
    }

    // Handle known macOS symlinks without syscalls
    #[cfg(target_os = "macos")]
    {
        // /tmp is a symlink to /private/tmp on macOS
        if path_str == "/tmp" || path_str.starts_with("/tmp/") {
            path_str = path_str.replacen("/tmp", "/private/tmp", 1);
        }
        // /var is a symlink to /private/var on macOS
        if path_str == "/var" || path_str.starts_with("/var/") {
            path_str = path_str.replacen("/var", "/private/var", 1);
        }
        // /etc is a symlink to /private/etc on macOS
        if path_str == "/etc" || path_str.starts_with("/etc/") {
            path_str = path_str.replacen("/etc", "/private/etc", 1);
        }
    }

    PathBuf::from(path_str)
}

/// Result of checking mount point accessibility
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPointStatus {
    /// Path is accessible and ready for use
    Available,
    /// Path exists and appears to be a stale/unresponsive mount
    StaleMountDetected,
    /// Path doesn't exist (may need to be created)
    DoesNotExist,
    /// Path exists but is a regular file (not usable as mount point)
    NotADirectory,
    /// Parent directory is inaccessible (possibly stale mount)
    ParentInaccessible,
    /// Path is already a mount point
    AlreadyMounted,
    /// Some other error occurred
    Error(String),
}

// ============================================================================
// Non-blocking mount table functions (preferred)
// ============================================================================

/// Check if a path is already a mount point using the system mount table.
///
/// This is a non-blocking check that never touches the filesystem.
///
/// # Returns
///
/// `Some(mount)` if the path is a mountpoint, `None` otherwise.
pub fn is_path_mounted(path: &Path) -> Option<SystemMount> {
    let system_mounts = get_system_mounts_detailed().ok()?;
    let normalized = normalize_mount_path(path);

    system_mounts.into_iter().find(|m| {
        let mount_normalized = normalize_mount_path(&m.mountpoint);
        mount_normalized == normalized
    })
}

/// Check if a path is under a FUSE mount point using the system mount table.
///
/// This is a non-blocking check that never touches the filesystem.
///
/// # Returns
///
/// `Some(mountpoint)` if the path is under a FUSE mount, `None` otherwise.
pub fn is_under_fuse_mount(path: &Path) -> Option<PathBuf> {
    let system_mounts = get_system_mounts_detailed().ok()?;
    let normalized = normalize_mount_path(path);
    let path_str = normalized.to_string_lossy();

    for mount in system_mounts {
        if crate::mount_markers::is_fuse_fstype(&mount.fstype) {
            let mount_str = mount.mountpoint.to_string_lossy();
            if path_str.starts_with(mount_str.as_ref()) {
                return Some(mount.mountpoint);
            }
        }
    }
    None
}

// ============================================================================
// Deprecated probing functions (leak threads on ghost mounts)
// ============================================================================

/// Check if a path is accessible within a timeout.
///
/// # Deprecation Warning
///
/// This function spawns a thread that may leak if the path is on a ghost mount.
/// Prefer using [`is_path_mounted`] or [`is_under_fuse_mount`] for mount detection.
#[deprecated(
    since = "0.2.0",
    note = "Leaks threads on ghost mounts. Use is_path_mounted() for mount detection."
)]
pub fn is_path_accessible(path: &Path, timeout: Duration) -> bool {
    use crate::bounded_pool::BOUNDED_FS_POOL;

    let path = path.to_path_buf();
    BOUNDED_FS_POOL
        .run_with_timeout(timeout, move || {
            std::fs::metadata(&path).map(|_| true)
        })
        .unwrap_or(false)
}

/// Check if a directory is readable within a timeout.
///
/// # Deprecation Warning
///
/// This function spawns a thread that may leak if the path is on a ghost mount.
/// Prefer using [`is_path_mounted`] for mount detection.
#[deprecated(
    since = "0.2.0",
    note = "Leaks threads on ghost mounts. Use is_path_mounted() for mount detection."
)]
pub fn is_directory_readable(path: &Path, timeout: Duration) -> bool {
    use crate::bounded_pool::BOUNDED_FS_POOL;
    use std::io;

    let path = path.to_path_buf();
    BOUNDED_FS_POOL
        .run_with_timeout(timeout, move || {
            std::fs::read_dir(&path)
                .map(|mut entries| {
                    let _ = entries.next();
                    true
                })
                .map_err(|e| io::Error::new(e.kind(), e))
        })
        .unwrap_or(false)
}

/// Check the status of a potential mount point.
///
/// # Deprecation Warning
///
/// This function probes the filesystem and may leak threads on ghost mounts.
/// Use [`is_path_mounted`] instead for non-blocking mount detection.
#[deprecated(
    since = "0.2.0",
    note = "Leaks threads on ghost mounts. Use is_path_mounted() instead."
)]
pub fn check_mountpoint_status(path: &Path, timeout: Duration) -> MountPointStatus {
    use crate::bounded_pool::BOUNDED_FS_POOL;
    use std::io;

    // First check mount table (non-blocking)
    if is_path_mounted(path).is_some() {
        return MountPointStatus::AlreadyMounted;
    }

    // Check parent with probe (may leak)
    #[allow(deprecated)]
    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() || parent == Path::new("/") {
            // Root or empty parent, skip check
        } else if !is_path_accessible(parent, timeout) {
            return MountPointStatus::ParentInaccessible;
        }
    }

    let path_buf = path.to_path_buf();

    let result = BOUNDED_FS_POOL.run_with_timeout(timeout, move || {
        match std::fs::metadata(&path_buf) {
            Ok(meta) => {
                if meta.is_dir() {
                    match std::fs::read_dir(&path_buf) {
                        Ok(mut entries) => {
                            let _ = entries.next();
                            Ok(MountPointStatus::Available)
                        }
                        Err(_) => Ok(MountPointStatus::StaleMountDetected),
                    }
                } else {
                    Ok(MountPointStatus::NotADirectory)
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(MountPointStatus::DoesNotExist),
            Err(e) => Ok(MountPointStatus::Error(e.to_string())),
        }
    });

    match result {
        Ok(status) => status,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => MountPointStatus::StaleMountDetected,
        Err(e) if e.kind() == io::ErrorKind::ResourceBusy => {
            MountPointStatus::Error("Too many blocked threads - possible ghost mounts".to_string())
        }
        Err(e) => MountPointStatus::Error(e.to_string()),
    }
}

/// Check if a path is likely on a FUSE filesystem by parsing mount table.
///
/// This is a non-blocking check that reads system mount information.
#[cfg(target_os = "macos")]
pub fn is_on_fuse_mount(path: &Path) -> Option<PathBuf> {
    use std::process::Command;

    // Get mount table
    let output = Command::new("mount").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let path_str = path.to_string_lossy();

    // Look for FUSE mounts that are parents of our path
    for line in stdout.lines() {
        // macOS mount output: /dev/xxx on /path (type, options)
        // macFUSE: mount_macfuse@xxx on /path (macfuse, options)
        if line.contains("macfuse") || line.contains("osxfuse") || line.contains("fuse") {
            // Extract mount point (between "on " and " (")
            if let Some(start) = line.find(" on ") {
                let rest = &line[start + 4..];
                if let Some(end) = rest.find(" (") {
                    let mount_point = &rest[..end];
                    // Check if our path is under this mount point
                    if path_str.starts_with(mount_point) || path_str == mount_point {
                        return Some(PathBuf::from(mount_point));
                    }
                }
            }
        }
    }

    None
}

/// Check if a path is likely on a FUSE filesystem by parsing mount table.
#[cfg(target_os = "linux")]
pub fn is_on_fuse_mount(path: &Path) -> Option<PathBuf> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let path_str = path.to_string_lossy();

    // Read /proc/mounts
    let file = File::open("/proc/mounts").ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let mount_point = parts[1];
            let fs_type = parts[2];

            // Check for FUSE filesystem types
            if fs_type.starts_with("fuse") || fs_type == "fuseblk" {
                if path_str.starts_with(mount_point) || path_str == mount_point {
                    return Some(PathBuf::from(mount_point));
                }
            }
        }
    }

    None
}

/// Stub for unsupported platforms
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn is_on_fuse_mount(_path: &Path) -> Option<PathBuf> {
    None
}

/// Find an available mount point, trying suffixes if the original is unavailable.
///
/// If `base_path` is `/path/to/vault`, this will try:
/// 1. `/path/to/vault`
/// 2. `/path/to/vault-2`
/// 3. `/path/to/vault-3`
///
/// ...up to `/path/to/vault-99`
///
/// # Non-blocking Design
///
/// This function only checks the system mount table. It does NOT probe the filesystem,
/// which means it won't block on ghost FUSE mounts.
///
/// A path is considered "available" if it's not already a mount point. The caller
/// is responsible for:
/// - Creating the directory if it doesn't exist
/// - Handling any filesystem errors during the actual mount operation
///
/// # Arguments
///
/// * `base_path` - The preferred mount point path
///
/// # Returns
///
/// The first path that is not already a mount point, or an error if none found.
pub fn find_available_mountpoint(base_path: &Path) -> Result<PathBuf, MountPointError> {
    // Check if parent is under a FUSE mount (potential ghost mount issue)
    // This is informational only - we can't know if it's stale without probing
    if let Some(parent) = base_path.parent()
        && !parent.as_os_str().is_empty()
        && parent != Path::new("/")
        && let Some(fuse_mount) = is_under_fuse_mount(parent)
    {
        tracing::debug!(
            "Parent {} is under FUSE mount {}",
            parent.display(),
            fuse_mount.display()
        );
        // We don't block here - let the actual mount operation fail if there's a problem
    }

    // Try the base path first
    if is_path_mounted(base_path).is_none() {
        // Not a mount point - available
        return Ok(base_path.to_path_buf());
    }

    tracing::debug!(
        "Path {} is already a mount point, trying alternatives",
        base_path.display()
    );

    // Try with suffixes
    let base_str = base_path.to_string_lossy();
    for suffix in 2..=MAX_SUFFIX {
        let suffixed_path = PathBuf::from(format!("{base_str}-{suffix}"));

        if is_path_mounted(&suffixed_path).is_none() {
            tracing::info!(
                "Using alternative mount point: {}",
                suffixed_path.display()
            );
            return Ok(suffixed_path);
        }
    }

    Err(MountPointError::NoAvailablePath {
        base: base_path.to_path_buf(),
        tried: MAX_SUFFIX,
    })
}

/// Errors that can occur when finding a mount point.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MountPointError {
    /// Could not find any available mount point path
    #[error(
        "Could not find available mount point. Tried {} through {}-{}",
        base.display(),
        base.display(),
        tried
    )]
    NoAvailablePath {
        /// The base path that was tried
        base: PathBuf,
        /// Number of suffixes tried
        tried: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_is_path_accessible_existing() {
        let temp = TempDir::new().unwrap();
        assert!(is_path_accessible(temp.path(), DEFAULT_ACCESS_TIMEOUT));
    }

    #[test]
    fn test_is_path_accessible_nonexistent() {
        let path = Path::new("/nonexistent/path/12345");
        assert!(!is_path_accessible(path, DEFAULT_ACCESS_TIMEOUT));
    }

    #[test]
    fn test_check_mountpoint_status_doesnt_exist() {
        let path = Path::new("/tmp/nonexistent_mount_test_12345");
        let status = check_mountpoint_status(path, DEFAULT_ACCESS_TIMEOUT);
        assert_eq!(status, MountPointStatus::DoesNotExist);
    }

    #[test]
    fn test_check_mountpoint_status_available() {
        let temp = TempDir::new().unwrap();
        let status = check_mountpoint_status(temp.path(), DEFAULT_ACCESS_TIMEOUT);
        assert_eq!(status, MountPointStatus::Available);
    }

    #[test]
    fn test_check_mountpoint_status_not_a_directory() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("file.txt");
        fs::write(&file_path, "test").unwrap();

        let status = check_mountpoint_status(&file_path, DEFAULT_ACCESS_TIMEOUT);
        assert_eq!(status, MountPointStatus::NotADirectory);
    }

    #[test]
    fn test_find_available_mountpoint_returns_base_when_not_mounted() {
        // Test that find_available_mountpoint returns the base path when it's not a mount point
        // Since we can't easily create mock mount points, we test with a path that definitely
        // isn't a mount point
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("vault");

        let result = find_available_mountpoint(&base);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), base);
    }

    #[test]
    fn test_find_available_mountpoint_with_existing_dir() {
        // Creating a directory does NOT make it a mount point, so it should still be returned
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("vault");

        // Create base directory with content - this is NOT a mount point
        fs::create_dir(&base).unwrap();
        fs::write(base.join("file.txt"), "content").unwrap();

        // Should still return base because it's not a mount point
        let result = find_available_mountpoint(&base);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), base);
    }

    #[test]
    fn test_find_available_mountpoint_nonexistent_path() {
        // A nonexistent path is also not a mount point
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("nonexistent_vault");

        let result = find_available_mountpoint(&base);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), base);
    }

    #[test]
    fn test_is_on_fuse_mount_regular_path() {
        // A regular path should not be detected as FUSE
        let result = is_on_fuse_mount(Path::new("/tmp"));
        assert!(result.is_none());
    }
}
