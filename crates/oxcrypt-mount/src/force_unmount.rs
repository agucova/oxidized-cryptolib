//! Platform-specific force unmount utilities.
//!
//! This module provides utilities to forcibly unmount filesystems when
//! graceful unmount is not possible (e.g., stale mounts, crashed daemons).
//!
//! # Safety
//!
//! **IMPORTANT**: Callers must verify that the mount belongs to them before
//! calling these functions. These functions will attempt to unmount ANY path
//! without verification.
//!
//! Use `mount_markers::is_our_mount()` before calling `force_unmount()`.
//!
//! # Platform Support
//!
//! - **macOS**: Uses `diskutil unmount force`, falls back to `umount -f`
//! - **Linux**: Uses `fusermount -uz` (lazy unmount), falls back to `umount -l`
//! - **Other**: Returns an error (unsupported)

use std::path::Path;
use std::process::Command;

use anyhow::Result;

/// Force unmount a filesystem at the given path.
///
/// # Safety
///
/// **Caller must verify ownership** before calling this function!
/// Use `mount_markers::is_our_mount()` to verify the mount has our markers.
///
/// # Behavior
///
/// - On macOS: Tries `diskutil unmount force`, then `umount -f`
/// - On Linux: Tries `fusermount -uz`, then `umount -l`
/// - Other platforms: Returns error
///
/// # Errors
///
/// Returns an error if all unmount attempts fail.
pub fn force_unmount(mountpoint: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        force_unmount_macos(mountpoint)
    }

    #[cfg(target_os = "linux")]
    {
        force_unmount_linux(mountpoint)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!(
            "Force unmount not supported on this platform for {}",
            mountpoint.display()
        )
    }
}

/// Attempt a lazy/deferred unmount.
///
/// This immediately removes the mount from the namespace but allows
/// existing file handles to continue until they're closed.
///
/// # Safety
///
/// Same as `force_unmount` - caller must verify ownership.
pub fn lazy_unmount(mountpoint: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // macOS doesn't have true lazy unmount, use force unmount
        force_unmount_macos(mountpoint)
    }

    #[cfg(target_os = "linux")]
    {
        lazy_unmount_linux(mountpoint)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!(
            "Lazy unmount not supported on this platform for {}",
            mountpoint.display()
        )
    }
}

// ============================================================================
// macOS implementation
// ============================================================================

#[cfg(target_os = "macos")]
fn force_unmount_macos(mountpoint: &Path) -> Result<()> {
    use std::sync::mpsc;
    use std::time::Duration;

    // NOTE: We intentionally skip checking mountpoint.exists() here because:
    // 1. On ghost mounts, exists() blocks forever waiting for dead FUSE daemon
    // 2. The unmount commands will fail gracefully if there's nothing to unmount
    // 3. If the directory was deleted, diskutil/umount will just return an error

    // Try diskutil unmount force first (most reliable on macOS)
    // Use timeout to avoid hanging on ghost mounts
    let (tx, rx) = mpsc::channel();
    let mountpoint_clone = mountpoint.to_path_buf();

    std::thread::spawn(move || {
        let result = Command::new("diskutil")
            .args(["unmount", "force"])
            .arg(&mountpoint_clone)
            .output();
        let _ = tx.send(result);
    });

    if let Ok(Ok(result)) = rx.recv_timeout(Duration::from_secs(3)) {
        if result.status.success() {
            tracing::debug!(
                "Force unmount via diskutil succeeded for {}",
                mountpoint.display()
            );
            return Ok(());
        }

        // Log diskutil failure and try fallback
        let stderr = String::from_utf8_lossy(&result.stderr);
        tracing::debug!(
            "diskutil unmount failed for {}: {}",
            mountpoint.display(),
            stderr.trim()
        );
    } else {
        tracing::warn!(
            "diskutil unmount timed out for {} (possible ghost mount)",
            mountpoint.display()
        );
    }

    // Fallback to umount -f with timeout
    let (tx, rx) = mpsc::channel();
    let mountpoint_clone = mountpoint.to_path_buf();

    std::thread::spawn(move || {
        let result = Command::new("umount")
            .arg("-f")
            .arg(&mountpoint_clone)
            .output();
        let _ = tx.send(result);
    });

    if let Ok(Ok(result)) = rx.recv_timeout(Duration::from_secs(3)) {
        if result.status.success() {
            tracing::debug!(
                "Force unmount via umount -f succeeded for {}",
                mountpoint.display()
            );
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&result.stderr);
        anyhow::bail!(
            "Failed to force unmount {}: {}",
            mountpoint.display(),
            stderr.trim()
        )
    }

    // Both methods timed out - likely a ghost mount
    anyhow::bail!(
        "Failed to force unmount {} (timed out - possible ghost mount). \
        You may need to reboot to clear this mount.",
        mountpoint.display()
    )
}

// ============================================================================
// Linux implementation
// ============================================================================

#[cfg(target_os = "linux")]
fn force_unmount_linux(mountpoint: &Path) -> Result<()> {
    // Try fusermount -uz first (FUSE-specific, with lazy unmount)
    let result = Command::new("fusermount")
        .args(["-uz"])
        .arg(mountpoint)
        .output();

    match result {
        Ok(output) if output.status.success() => {
            tracing::debug!(
                "Force unmount via fusermount -uz succeeded for {}",
                mountpoint.display()
            );
            return Ok(());
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::debug!(
                "fusermount -uz failed for {}: {}",
                mountpoint.display(),
                stderr.trim()
            );
        }
        Err(e) => {
            tracing::debug!("fusermount not available: {}", e);
        }
    }

    // Fallback to umount -l (lazy unmount, works for any filesystem)
    let result = Command::new("umount")
        .arg("-l")
        .arg(mountpoint)
        .output()
        .context("Failed to run umount")?;

    if result.status.success() {
        tracing::debug!(
            "Force unmount via umount -l succeeded for {}",
            mountpoint.display()
        );
        return Ok(());
    }

    // Last resort: umount -f (force)
    let result = Command::new("umount")
        .arg("-f")
        .arg(mountpoint)
        .output()
        .context("Failed to run umount -f")?;

    if result.status.success() {
        tracing::debug!(
            "Force unmount via umount -f succeeded for {}",
            mountpoint.display()
        );
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&result.stderr);
    anyhow::bail!(
        "Failed to force unmount {}: {}",
        mountpoint.display(),
        stderr.trim()
    )
}

#[cfg(target_os = "linux")]
fn lazy_unmount_linux(mountpoint: &Path) -> Result<()> {
    // Try fusermount -uz first
    let result = Command::new("fusermount")
        .args(["-uz"])
        .arg(mountpoint)
        .output();

    if let Ok(output) = result {
        if output.status.success() {
            tracing::debug!(
                "Lazy unmount via fusermount -uz succeeded for {}",
                mountpoint.display()
            );
            return Ok(());
        }
    }

    // Fallback to umount -l
    let result = Command::new("umount")
        .arg("-l")
        .arg(mountpoint)
        .output()
        .context("Failed to run umount -l")?;

    if result.status.success() {
        tracing::debug!(
            "Lazy unmount via umount -l succeeded for {}",
            mountpoint.display()
        );
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&result.stderr);
    anyhow::bail!(
        "Failed to lazy unmount {}: {}",
        mountpoint.display(),
        stderr.trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_force_unmount_nonexistent_path() {
        // Trying to unmount a path that isn't mounted should fail
        let result = force_unmount(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_err());
    }

    // Note: Actual unmount tests would require creating real mounts,
    // which is done in integration tests rather than unit tests.
}
