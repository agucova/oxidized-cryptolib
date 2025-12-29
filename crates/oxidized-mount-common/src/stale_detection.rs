//! Stale mount detection for cleanup operations.
//!
//! This module provides utilities to determine whether a mount is stale
//! (safe to cleanup) or active (must not touch).
//!
//! # Safety Philosophy
//!
//! A mount is only considered stale if ALL of these are true:
//! 1. It has our markers (verified by `mount_markers::is_our_mount`)
//! 2. The owning process is dead
//! 3. The mount still exists in the system mount table
//!
//! We NEVER auto-unmount orphaned mounts (ours but not tracked) - we only warn.

use std::path::Path;
use std::time::Duration;

use crate::mount_markers::{find_our_mounts, is_our_mount, SystemMount};
use crate::mount_utils::is_directory_readable;

/// Classification of a mount's status for cleanup decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountStatus {
    /// Mount is active - process alive and mount responsive.
    /// NEVER cleanup.
    Active,

    /// Mount is stale - safe to cleanup.
    Stale {
        /// Why we consider this mount stale
        reason: StaleReason,
    },

    /// Mount is orphaned - ours but not in the tracking state.
    /// Should WARN but NOT auto-cleanup.
    Orphaned,

    /// Mount is foreign - does not have our markers.
    /// NEVER touch.
    Foreign,

    /// Could not determine status.
    Unknown {
        /// Error message explaining the failure
        error: String,
    },
}

/// Reasons why a mount is considered stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleReason {
    /// The process that created the mount is no longer running.
    ProcessDead {
        /// The PID that was recorded when the mount was created
        pid: u32,
    },

    /// The mount is tracked in state but not present in system mounts.
    /// (Already unmounted, just need to clean up state)
    NotInSystemMounts,
}

/// Information about a tracked mount for status checking.
///
/// This is a lightweight struct that can be constructed from any
/// state management system (CLI's MountEntry, GUI's mount tracking, etc.)
#[derive(Debug, Clone)]
pub struct TrackedMount {
    /// The mount point path
    pub mountpoint: std::path::PathBuf,
    /// Process ID of the mount daemon/process
    pub pid: u32,
    /// Optional: filesystem name for marker verification
    pub fsname: Option<String>,
}

/// Check the status of a tracked mount.
///
/// This is the primary function for determining if a mount is safe to cleanup.
///
/// # Arguments
///
/// * `tracked` - Information about the tracked mount
/// * `system_mounts` - Current system mounts (from `get_system_mounts_detailed`)
/// * `check_timeout` - Timeout for responsiveness checks (recommended: 500ms)
///
/// # Safety Guarantees
///
/// This function will return:
/// - `MountStatus::Active` if the process is alive (even if mount is unresponsive)
/// - `MountStatus::Foreign` if the mount doesn't have our markers
/// - `MountStatus::Stale` only if process is dead AND mount exists
pub fn check_mount_status(
    tracked: &TrackedMount,
    system_mounts: &[SystemMount],
    check_timeout: Duration,
) -> MountStatus {
    // Step 1: Check if this mount is in the system mount table
    let system_mount = system_mounts
        .iter()
        .find(|m| m.mountpoint == tracked.mountpoint);

    // Step 2: If not in system mounts, it's already unmounted (just stale state entry)
    let Some(system_mount) = system_mount else {
        return MountStatus::Stale {
            reason: StaleReason::NotInSystemMounts,
        };
    };

    // Step 3: Verify this is our mount (critical safety check)
    if !is_our_mount(system_mount) {
        return MountStatus::Foreign;
    }

    // Step 4: Check if the owning process is still alive
    if is_process_alive(tracked.pid) {
        return MountStatus::Active;
    }

    // Step 5: Process is dead - this is a stale mount
    // Optional: verify mount is unresponsive (extra safety check)
    let _is_responsive = is_directory_readable(&tracked.mountpoint, check_timeout);

    // Even if responsive, if process is dead, consider it stale
    // (The mount might be in a zombie state that still responds to some operations)
    MountStatus::Stale {
        reason: StaleReason::ProcessDead { pid: tracked.pid },
    }
}

/// Find orphaned mounts - mounts with our markers but not in the tracked list.
///
/// These are mounts that:
/// - Have oxidized-cryptolib markers (fsname starts with "cryptomator:")
/// - Are NOT in the provided list of tracked mountpoints
///
/// # Safety
///
/// Orphaned mounts should be WARNED about but NOT automatically cleaned up,
/// because:
/// - They might be from another user running the same tool
/// - They might be from a process that crashed before writing state
/// - They might be intentionally mounted via a different mechanism
pub fn find_orphaned_mounts(tracked_mountpoints: &[&Path]) -> anyhow::Result<Vec<SystemMount>> {
    let our_mounts = find_our_mounts()?;

    let orphans: Vec<SystemMount> = our_mounts
        .into_iter()
        .filter(|m| !tracked_mountpoints.contains(&m.mountpoint.as_path()))
        .collect();

    Ok(orphans)
}

/// Check if a process with the given PID is alive.
///
/// Uses platform-specific mechanisms to check process existence.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    // kill(pid, 0) checks if process exists without sending a signal
    // Returns Ok(()) if process exists, Err with ESRCH if it doesn't
    kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    use std::process::Command;

    // Use tasklist to check if PID exists
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            !stdout.contains("No tasks") && stdout.contains(&pid.to_string())
        })
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
pub fn is_process_alive(_pid: u32) -> bool {
    // Assume alive on unsupported platforms (safe default)
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_tracked(mountpoint: &str, pid: u32) -> TrackedMount {
        TrackedMount {
            mountpoint: PathBuf::from(mountpoint),
            pid,
            fsname: Some("cryptomator:test".to_string()),
        }
    }

    fn make_system_mount(mountpoint: &str, fsname: &str) -> SystemMount {
        SystemMount {
            mountpoint: PathBuf::from(mountpoint),
            fstype: "macfuse".to_string(),
            fsname: fsname.to_string(),
        }
    }

    #[test]
    fn test_status_not_in_system_mounts() {
        let tracked = make_tracked("/mnt/vault", 12345);
        let system_mounts = vec![]; // No system mounts

        let status = check_mount_status(&tracked, &system_mounts, Duration::from_millis(100));

        assert_eq!(
            status,
            MountStatus::Stale {
                reason: StaleReason::NotInSystemMounts
            }
        );
    }

    #[test]
    fn test_status_foreign_mount() {
        let tracked = make_tracked("/mnt/vault", 12345);
        let system_mounts = vec![make_system_mount("/mnt/vault", "sshfs#user@host")];

        let status = check_mount_status(&tracked, &system_mounts, Duration::from_millis(100));

        assert_eq!(status, MountStatus::Foreign);
    }

    #[test]
    fn test_status_active_mount() {
        // Use current process PID (which is definitely alive)
        let current_pid = std::process::id();
        let tracked = make_tracked("/mnt/vault", current_pid);
        let system_mounts = vec![make_system_mount("/mnt/vault", "cryptomator:test")];

        let status = check_mount_status(&tracked, &system_mounts, Duration::from_millis(100));

        assert_eq!(status, MountStatus::Active);
    }

    #[test]
    fn test_status_stale_dead_process() {
        // Use a PID that almost certainly doesn't exist
        let dead_pid = u32::MAX - 1;
        let tracked = make_tracked("/mnt/vault", dead_pid);
        let system_mounts = vec![make_system_mount("/mnt/vault", "cryptomator:test")];

        let status = check_mount_status(&tracked, &system_mounts, Duration::from_millis(100));

        assert!(matches!(
            status,
            MountStatus::Stale {
                reason: StaleReason::ProcessDead { .. }
            }
        ));
    }

    #[test]
    fn test_is_process_alive_current() {
        // Current process is definitely alive
        assert!(is_process_alive(std::process::id()));
    }

    #[test]
    fn test_is_process_alive_nonexistent() {
        // Very high PID should not exist
        assert!(!is_process_alive(u32::MAX - 1));
    }

    #[test]
    fn test_find_orphaned_empty_tracked() {
        // With no tracked mounts, all our mounts would be orphans
        // (This is a unit test - actual system mounts would vary)
        let tracked: Vec<&Path> = vec![];
        let result = find_orphaned_mounts(&tracked);
        assert!(result.is_ok());
    }
}
