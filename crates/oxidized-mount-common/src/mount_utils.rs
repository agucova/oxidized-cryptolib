//! Mount point utilities for detecting stale mounts and finding available paths.
//!
//! When a FUSE daemon crashes without proper cleanup, the mount becomes "stale" -
//! any filesystem operation on it blocks indefinitely. This module provides
//! utilities to detect such situations and find alternative mount points.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Default timeout for filesystem accessibility checks
pub const DEFAULT_ACCESS_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum suffix number to try when finding alternative mount points
const MAX_SUFFIX: u32 = 99;

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
    /// Some other error occurred
    Error(String),
}

/// Check if a path is accessible within a timeout.
///
/// This spawns a thread to perform the check, avoiding blocking the caller
/// if the path is on a stale FUSE mount.
///
/// # Arguments
///
/// * `path` - The path to check
/// * `timeout` - Maximum time to wait for the check
///
/// # Returns
///
/// `true` if the path was accessible within the timeout, `false` otherwise.
pub fn is_path_accessible(path: &Path, timeout: Duration) -> bool {
    let path = path.to_path_buf();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        // Try to stat the path - this will block on stale mounts
        let result = std::fs::metadata(&path).is_ok();
        let _ = tx.send(result);
    });

    rx.recv_timeout(timeout).unwrap_or(false)
}

/// Check if a directory is readable within a timeout.
///
/// More thorough than `is_path_accessible` - actually tries to read directory entries.
pub fn is_directory_readable(path: &Path, timeout: Duration) -> bool {
    let path = path.to_path_buf();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = std::fs::read_dir(&path)
            .map(|mut entries| {
                // Try to actually iterate - confirms FUSE is responding
                let _ = entries.next();
                true
            })
            .unwrap_or(false);
        let _ = tx.send(result);
    });

    rx.recv_timeout(timeout).unwrap_or(false)
}

/// Check the status of a potential mount point.
///
/// Uses timeout-wrapped filesystem operations to avoid blocking on stale mounts.
pub fn check_mountpoint_status(path: &Path, timeout: Duration) -> MountPointStatus {
    // First, check if parent directory is accessible
    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() || parent == Path::new("/") {
            // Root or empty parent, skip check
        } else if !is_path_accessible(parent, timeout) {
            return MountPointStatus::ParentInaccessible;
        }
    }

    // Now check the path itself with a timeout
    let path_buf = path.to_path_buf();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        match std::fs::metadata(&path_buf) {
            Ok(meta) => {
                if meta.is_dir() {
                    // It's a directory - check if it's readable (not stale)
                    match std::fs::read_dir(&path_buf) {
                        Ok(mut entries) => {
                            // Try to iterate
                            let _ = entries.next();
                            tx.send(MountPointStatus::Available)
                        }
                        Err(_) => tx.send(MountPointStatus::StaleMountDetected),
                    }
                } else {
                    tx.send(MountPointStatus::NotADirectory)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tx.send(MountPointStatus::DoesNotExist)
            }
            Err(e) => tx.send(MountPointStatus::Error(e.to_string())),
        }
    });

    match rx.recv_timeout(timeout) {
        Ok(status) => status,
        Err(mpsc::RecvTimeoutError::Timeout) => MountPointStatus::StaleMountDetected,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            MountPointStatus::Error("Check thread panicked".to_string())
        }
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
/// # Arguments
///
/// * `base_path` - The preferred mount point path
/// * `timeout` - Timeout for accessibility checks
///
/// # Returns
///
/// The first available path, or an error if none found.
pub fn find_available_mountpoint(
    base_path: &Path,
    timeout: Duration,
) -> Result<PathBuf, MountPointError> {
    // First, check if parent directory is accessible
    if let Some(parent) = base_path.parent()
        && !parent.as_os_str().is_empty()
        && parent != Path::new("/")
    {
        match check_mountpoint_status(parent, timeout) {
            MountPointStatus::Available | MountPointStatus::DoesNotExist => {}
            MountPointStatus::StaleMountDetected | MountPointStatus::ParentInaccessible => {
                // Parent is on a stale mount - we can't create anything here
                if let Some(fuse_mount) = is_on_fuse_mount(parent) {
                    return Err(MountPointError::ParentOnStaleFuseMount {
                        parent: parent.to_path_buf(),
                        fuse_mount,
                    });
                }
                return Err(MountPointError::ParentInaccessible(parent.to_path_buf()));
            }
            MountPointStatus::NotADirectory => {
                return Err(MountPointError::ParentNotDirectory(parent.to_path_buf()));
            }
            MountPointStatus::Error(e) => {
                return Err(MountPointError::AccessError(e));
            }
        }
    }

    // Try the base path first
    match check_mountpoint_status(base_path, timeout) {
        MountPointStatus::Available => {
            // Path exists and is accessible - check if it's empty
            if is_directory_empty(base_path, timeout) {
                return Ok(base_path.to_path_buf());
            }
            // Directory not empty, might be an existing mount - try suffixes
        }
        MountPointStatus::DoesNotExist => {
            // Perfect - we can create it
            return Ok(base_path.to_path_buf());
        }
        MountPointStatus::StaleMountDetected => {
            // Stale mount at base path - try suffixes
            tracing::warn!(
                "Stale mount detected at {}, trying alternative paths",
                base_path.display()
            );
        }
        MountPointStatus::NotADirectory => {
            // There's a file here - try suffixes
        }
        MountPointStatus::ParentInaccessible => {
            // Already handled above, but just in case
            return Err(MountPointError::ParentInaccessible(
                base_path.parent().unwrap_or(base_path).to_path_buf(),
            ));
        }
        MountPointStatus::Error(e) => {
            return Err(MountPointError::AccessError(e));
        }
    }

    // Try with suffixes
    let base_str = base_path.to_string_lossy();
    for suffix in 2..=MAX_SUFFIX {
        let suffixed_path = PathBuf::from(format!("{}-{}", base_str, suffix));

        match check_mountpoint_status(&suffixed_path, timeout) {
            MountPointStatus::DoesNotExist => {
                tracing::info!(
                    "Using alternative mount point: {}",
                    suffixed_path.display()
                );
                return Ok(suffixed_path);
            }
            MountPointStatus::Available => {
                if is_directory_empty(&suffixed_path, timeout) {
                    tracing::info!(
                        "Using alternative mount point: {}",
                        suffixed_path.display()
                    );
                    return Ok(suffixed_path);
                }
                // Not empty, continue to next suffix
            }
            MountPointStatus::StaleMountDetected
            | MountPointStatus::NotADirectory
            | MountPointStatus::Error(_) => {
                // Keep trying
                continue;
            }
            MountPointStatus::ParentInaccessible => {
                // Same parent, won't work
                break;
            }
        }
    }

    Err(MountPointError::NoAvailablePath {
        base: base_path.to_path_buf(),
        tried: MAX_SUFFIX,
    })
}

/// Check if a directory is empty (with timeout protection).
fn is_directory_empty(path: &Path, timeout: Duration) -> bool {
    let path = path.to_path_buf();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = std::fs::read_dir(&path)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        let _ = tx.send(result);
    });

    rx.recv_timeout(timeout).unwrap_or(false)
}

/// Errors that can occur when finding a mount point.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MountPointError {
    /// Parent directory is on a stale FUSE mount
    #[error(
        "Cannot mount: parent directory {} is on a stale FUSE mount ({}). \
         Please unmount or force-unmount the stale mount first.",
        parent.display(),
        fuse_mount.display()
    )]
    ParentOnStaleFuseMount {
        /// The parent directory path
        parent: PathBuf,
        /// The FUSE mount point containing it
        fuse_mount: PathBuf,
    },

    /// Parent directory is inaccessible
    #[error("Parent directory {} is inaccessible", .0.display())]
    ParentInaccessible(PathBuf),

    /// Parent path is not a directory
    #[error("Parent path {} is not a directory", .0.display())]
    ParentNotDirectory(PathBuf),

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

    /// General access error
    #[error("Error accessing path: {0}")]
    AccessError(String),
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
    fn test_find_available_mountpoint_prefers_base() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("vault");

        let result = find_available_mountpoint(&base, DEFAULT_ACCESS_TIMEOUT);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), base);
    }

    #[test]
    fn test_find_available_mountpoint_uses_suffix_when_occupied() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("vault");

        // Create base directory with content
        fs::create_dir(&base).unwrap();
        fs::write(base.join("file.txt"), "content").unwrap();

        let result = find_available_mountpoint(&base, DEFAULT_ACCESS_TIMEOUT);
        assert!(result.is_ok());
        let found = result.unwrap();
        assert_eq!(found, temp.path().join("vault-2"));
    }

    #[test]
    fn test_find_available_mountpoint_skips_occupied_suffixes() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("vault");

        // Create base and -2 with content
        fs::create_dir(&base).unwrap();
        fs::write(base.join("file.txt"), "content").unwrap();

        let vault2 = temp.path().join("vault-2");
        fs::create_dir(&vault2).unwrap();
        fs::write(vault2.join("file.txt"), "content").unwrap();

        let result = find_available_mountpoint(&base, DEFAULT_ACCESS_TIMEOUT);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), temp.path().join("vault-3"));
    }

    #[test]
    fn test_is_on_fuse_mount_regular_path() {
        // A regular path should not be detected as FUSE
        let result = is_on_fuse_mount(Path::new("/tmp"));
        assert!(result.is_none());
    }
}
