//! Core stale mount cleanup orchestration.
//!
//! This module provides the main cleanup function that ties together mount
//! detection, stale identification, and force unmount operations.
//!
//! # Safety Guarantees
//!
//! The cleanup process enforces strict safety invariants:
//!
//! 1. **Never unmount if PID is alive** - Could be another instance
//! 2. **Never unmount without our markers** - Could be another program's mount
//! 3. **Never auto-unmount orphans by default** - Warn only, let user decide
//! 4. **Handle races** - Caller should use file locking on state operations
//!
//! # Usage
//!
//! ```ignore
//! use oxcrypt_mount::cleanup::{cleanup_stale_mounts, CleanupOptions, TrackedMountInfo};
//!
//! // Gather tracked mounts from your state management
//! let tracked_mounts = vec![
//!     TrackedMountInfo {
//!         mountpoint: PathBuf::from("/mnt/vault"),
//!         pid: 12345,
//!     },
//! ];
//!
//! let options = CleanupOptions::default();
//! let results = cleanup_stale_mounts(&tracked_mounts, &options)?;
//!
//! for result in results {
//!     match result.action {
//!         CleanupAction::Unmounted => println!("Cleaned: {}", result.mountpoint.display()),
//!         CleanupAction::Warning => println!("Warning: orphan at {}", result.mountpoint.display()),
//!         _ => {}
//!     }
//! }
//! ```

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::force_unmount::force_unmount;
use crate::mount_markers::{get_system_mounts_detailed, SystemMount};
use crate::stale_detection::{
    check_mount_status, find_orphaned_mounts, MountStatus, StaleReason, TrackedMount,
};

/// Result of cleaning up a single mount.
#[derive(Debug, Clone)]
pub struct CleanupResult {
    /// The mount point that was processed
    pub mountpoint: PathBuf,
    /// What action was taken
    pub action: CleanupAction,
    /// Whether the action succeeded
    pub success: bool,
    /// Error message if action failed
    pub error: Option<String>,
}

/// Action taken during cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupAction {
    /// Successfully force-unmounted a stale mount
    Unmounted,
    /// Removed from state (mount wasn't in system mounts)
    RemovedFromState,
    /// Skipped (active mount, foreign mount, etc.)
    Skipped {
        /// Reason for skipping
        reason: String,
    },
    /// Generated warning only (orphaned mount)
    Warning,
}

/// Options for cleanup behavior.
#[derive(Debug, Clone)]
pub struct CleanupOptions {
    /// Whether to actually unmount or just report what would be done
    pub dry_run: bool,
    /// Whether to detect and warn about orphaned mounts (default: true)
    pub warn_orphans: bool,
    /// Whether to auto-clean orphaned mounts (aggressive - use with caution)
    pub cleanup_orphans: bool,
}

impl Default for CleanupOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            warn_orphans: true,
            cleanup_orphans: false,
        }
    }
}

/// Information about a tracked mount for cleanup.
///
/// This is a simplified version of mount tracking information that can
/// be provided by any state management system.
#[derive(Debug, Clone)]
pub struct TrackedMountInfo {
    /// The mount point path
    pub mountpoint: PathBuf,
    /// Process ID that created the mount
    pub pid: u32,
}

/// Clean up stale mounts with actual force unmount.
///
/// This is the main cleanup function. It processes a list of tracked mounts,
/// identifies which are stale, and force-unmounts them.
///
/// # Arguments
///
/// * `tracked_mounts` - List of mounts being tracked by the caller's state system
/// * `options` - Cleanup behavior options
///
/// # Returns
///
/// A list of results describing what action was taken for each mount.
///
/// # Safety
///
/// This function will:
/// - NEVER unmount a mount whose process is still alive
/// - NEVER unmount a mount without our markers (cryptomator:*)
/// - NEVER auto-unmount orphaned mounts unless `cleanup_orphans` is enabled
///
/// # Example
///
/// ```ignore
/// let tracked = vec![
///     TrackedMountInfo { mountpoint: "/mnt/v1".into(), pid: 1234 },
///     TrackedMountInfo { mountpoint: "/mnt/v2".into(), pid: 5678 },
/// ];
/// let results = cleanup_stale_mounts(&tracked, &CleanupOptions::default())?;
/// ```
pub fn cleanup_stale_mounts(
    tracked_mounts: &[TrackedMountInfo],
    options: &CleanupOptions,
) -> Result<Vec<CleanupResult>> {
    let mut results = Vec::new();

    // Get current system mounts
    let system_mounts = get_system_mounts_detailed()?;

    // Process each tracked mount
    for tracked in tracked_mounts {
        let result = process_tracked_mount(tracked, &system_mounts, options);
        results.push(result);
    }

    // Optionally detect and warn/cleanup orphaned mounts
    if options.warn_orphans || options.cleanup_orphans {
        let tracked_paths: Vec<&Path> = tracked_mounts
            .iter()
            .map(|t| t.mountpoint.as_path())
            .collect();

        match find_orphaned_mounts(&tracked_paths) {
            Ok(orphans) => {
                if options.cleanup_orphans {
                    results.extend(cleanup_orphaned_mounts(orphans, options));
                } else if options.warn_orphans {
                    for orphan in orphans {
                        results.push(CleanupResult {
                            mountpoint: orphan.mountpoint,
                            action: CleanupAction::Warning,
                            success: true,
                            error: None,
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to detect orphaned mounts: {}", e);
            }
        }
    }

    Ok(results)
}

fn cleanup_orphaned_mounts(
    orphans: Vec<SystemMount>,
    options: &CleanupOptions,
) -> Vec<CleanupResult> {
    let mut results = Vec::new();

    for orphan in orphans {
        // For orphaned mounts, we can't safely determine if they're stale without probing
        // (which could block on ghost mounts). If cleanup_orphans is enabled, we force
        // unmount. Otherwise, we just warn.
        //
        // This is aggressive but safe: if someone is actively using an orphaned mount,
        // they can re-mount it after cleanup.

        if options.dry_run {
            tracing::info!(
                "[DRY RUN] Would force unmount orphaned mount {}",
                orphan.mountpoint.display()
            );
            results.push(CleanupResult {
                mountpoint: orphan.mountpoint,
                action: CleanupAction::Unmounted,
                success: true,
                error: None,
            });
            continue;
        }

        tracing::info!(
            "Force unmounting orphaned mount {}",
            orphan.mountpoint.display()
        );

        match force_unmount(&orphan.mountpoint) {
            Ok(()) => results.push(CleanupResult {
                mountpoint: orphan.mountpoint,
                action: CleanupAction::Unmounted,
                success: true,
                error: None,
            }),
            Err(e) => results.push(CleanupResult {
                mountpoint: orphan.mountpoint,
                action: CleanupAction::Unmounted,
                success: false,
                error: Some(e.to_string()),
            }),
        }
    }

    results
}

/// Process a single tracked mount for cleanup.
fn process_tracked_mount(
    tracked: &TrackedMountInfo,
    system_mounts: &[SystemMount],
    options: &CleanupOptions,
) -> CleanupResult {
    // Convert to the format expected by stale_detection
    let tracked_mount = TrackedMount {
        mountpoint: tracked.mountpoint.clone(),
        pid: tracked.pid,
        fsname: None,
    };

    // Check mount status (non-blocking - uses mount table + process check only)
    let status = check_mount_status(&tracked_mount, system_mounts);

    match status {
        MountStatus::Active => CleanupResult {
            mountpoint: tracked.mountpoint.clone(),
            action: CleanupAction::Skipped {
                reason: "Mount is active (process alive)".to_string(),
            },
            success: true,
            error: None,
        },

        MountStatus::Foreign => CleanupResult {
            mountpoint: tracked.mountpoint.clone(),
            action: CleanupAction::Skipped {
                reason: "Mount does not have our markers (foreign)".to_string(),
            },
            success: true,
            error: None,
        },

        MountStatus::Orphaned => CleanupResult {
            mountpoint: tracked.mountpoint.clone(),
            action: CleanupAction::Warning,
            success: true,
            error: None,
        },

        MountStatus::Unknown { error } => CleanupResult {
            mountpoint: tracked.mountpoint.clone(),
            action: CleanupAction::Skipped {
                reason: format!("Could not determine status: {error}"),
            },
            success: false,
            error: Some(error),
        },

        MountStatus::Stale { reason } => {
            handle_stale_mount(tracked, reason, options)
        }
    }
}

/// Handle a mount that has been identified as stale.
fn handle_stale_mount(
    tracked: &TrackedMountInfo,
    reason: StaleReason,
    options: &CleanupOptions,
) -> CleanupResult {
    match reason {
        StaleReason::NotInSystemMounts => {
            // Mount is no longer in system - just needs state cleanup
            tracing::debug!(
                "Mount {} is not in system mounts, marking for state removal",
                tracked.mountpoint.display()
            );
            CleanupResult {
                mountpoint: tracked.mountpoint.clone(),
                action: CleanupAction::RemovedFromState,
                success: true,
                error: None,
            }
        }

        StaleReason::ProcessDead { pid } => {
            // Mount exists but process is dead - force unmount needed
            if options.dry_run {
                tracing::info!(
                    "[DRY RUN] Would force unmount {} (PID {} dead)",
                    tracked.mountpoint.display(),
                    pid
                );
                return CleanupResult {
                    mountpoint: tracked.mountpoint.clone(),
                    action: CleanupAction::Unmounted,
                    success: true,
                    error: None,
                };
            }

            tracing::info!(
                "Force unmounting stale mount {} (PID {} dead)",
                tracked.mountpoint.display(),
                pid
            );

            match force_unmount(&tracked.mountpoint) {
                Ok(()) => CleanupResult {
                    mountpoint: tracked.mountpoint.clone(),
                    action: CleanupAction::Unmounted,
                    success: true,
                    error: None,
                },
                Err(e) => {
                    let error_msg = format!("Failed to force unmount: {e}");
                    tracing::error!(
                        "Failed to force unmount {}: {}",
                        tracked.mountpoint.display(),
                        e
                    );
                    CleanupResult {
                        mountpoint: tracked.mountpoint.clone(),
                        action: CleanupAction::Unmounted,
                        success: false,
                        error: Some(error_msg),
                    }
                }
            }
        }
    }
}

/// Clean up test mounts specifically.
///
/// This is a convenience function for test harnesses that cleans up
/// any mounts with `cryptomator-test` or `cryptomator:test` in their fsname.
///
/// Unlike the main cleanup function, this does NOT require tracked mounts -
/// it finds and force unmounts ALL test mounts. Since test mounts are explicitly
/// for testing, we can be aggressive about cleanup.
pub fn cleanup_test_mounts() -> Result<Vec<CleanupResult>> {
    use crate::mount_markers::find_our_mounts;

    let mut results = Vec::new();
    let our_mounts = find_our_mounts()?;

    for mount in our_mounts {
        // Only clean test mounts
        if !mount.fsname.contains("cryptomator-test") && !mount.fsname.contains("cryptomator:test")
        {
            continue;
        }

        // Force unmount test mount (no responsiveness check - tests should be robust)
        tracing::info!(
            "Cleaning up test mount: {}",
            mount.mountpoint.display()
        );

        match force_unmount(&mount.mountpoint) {
            Ok(()) => {
                results.push(CleanupResult {
                    mountpoint: mount.mountpoint,
                    action: CleanupAction::Unmounted,
                    success: true,
                    error: None,
                });
            }
            Err(e) => {
                results.push(CleanupResult {
                    mountpoint: mount.mountpoint,
                    action: CleanupAction::Unmounted,
                    success: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_options_default() {
        let options = CleanupOptions::default();
        assert!(!options.dry_run);
        assert!(options.warn_orphans);
        assert!(!options.cleanup_orphans);
    }

    #[test]
    fn test_cleanup_empty_tracked() {
        let tracked: Vec<TrackedMountInfo> = vec![];
        let options = CleanupOptions {
            warn_orphans: false, // Disable orphan detection for this test
            cleanup_orphans: false,
            ..Default::default()
        };

        let results = cleanup_stale_mounts(&tracked, &options).unwrap();
        // With no tracked mounts and orphan detection disabled, should be empty
        assert!(results.is_empty());
    }

    #[test]
    fn test_cleanup_result_display() {
        let result = CleanupResult {
            mountpoint: PathBuf::from("/mnt/test"),
            action: CleanupAction::Unmounted,
            success: true,
            error: None,
        };
        assert_eq!(result.action, CleanupAction::Unmounted);
        assert!(result.success);
    }
}
