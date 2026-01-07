//! Unmount command - unmount a previously mounted Cryptomator vault.
//!
//! Uses platform-specific tools:
//! - macOS: `umount` or `diskutil unmount`
//! - Linux: `fusermount -u` or `umount`
//!
//! For daemon mounts, attempts graceful shutdown via SIGTERM before
//! falling back to platform unmount tools.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tracing::instrument;

use crate::state::{is_process_alive, MountStateManager};

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Directory where the vault is mounted
    pub mountpoint: PathBuf,

    /// Force unmount even if the filesystem is busy
    #[arg(short, long)]
    pub force: bool,
}

#[instrument(level = "info", name = "cmd::unmount", skip_all, fields(mountpoint = %args.mountpoint.display(), force = args.force))]
pub fn execute(args: &Args) -> Result<()> {
    let mountpoint = &args.mountpoint;

    // Check if mountpoint exists
    if !mountpoint.exists() {
        // Maybe it's already unmounted but still in state file - try cleanup
        if let Ok(manager) = MountStateManager::new()
            && manager.remove_by_mountpoint(mountpoint)?
        {
            eprintln!("Removed stale mount entry for {}", mountpoint.display());
            return Ok(());
        }
        anyhow::bail!("Mountpoint does not exist: {}", mountpoint.display());
    }

    // Check state file for this mount
    let mount_entry = MountStateManager::new()
        .ok()
        .and_then(|m| m.find_by_mountpoint(mountpoint).ok().flatten());

    // If this is a daemon mount with a live process, try graceful shutdown first
    if let Some(ref entry) = mount_entry
        && entry.is_daemon
        && is_process_alive(entry.pid)
    {
        eprintln!(
            "Sending shutdown signal to daemon process (PID: {})...",
            entry.pid
        );

        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            // SAFETY: PIDs are always positive in practice. We use wrapping cast here
            // because the system may theoretically have very large PIDs, though this
            // is extremely rare. The nix crate requires i32, but system PIDs are u32.
            #[allow(clippy::cast_possible_wrap)]
            let pid = Pid::from_raw(entry.pid as i32);

            // Send SIGTERM for graceful shutdown
            if kill(pid, Signal::SIGTERM).is_ok() {
                // Wait up to 3 seconds for graceful shutdown
                for _ in 0..30 {
                    std::thread::sleep(Duration::from_millis(100));
                    if !is_process_alive(entry.pid) {
                        eprintln!("Daemon process exited gracefully");
                        // Clean up state file
                        if let Ok(manager) = MountStateManager::new() {
                            let _ = manager.remove_by_mountpoint(mountpoint);
                        }
                        // Check if mountpoint is still mounted
                        if !is_still_mounted(mountpoint) {
                            eprintln!("Unmounted successfully");
                            return Ok(());
                        }
                        break;
                    }
                }

                // If still alive after 3 seconds, send SIGKILL
                if is_process_alive(entry.pid) {
                    eprintln!("Daemon not responding to SIGTERM, sending SIGKILL...");
                    if kill(pid, Signal::SIGKILL).is_ok() {
                        // Wait briefly for SIGKILL to take effect
                        for _ in 0..10 {
                            std::thread::sleep(Duration::from_millis(100));
                            if !is_process_alive(entry.pid) {
                                eprintln!("Daemon process killed");
                                if let Ok(manager) = MountStateManager::new() {
                                    let _ = manager.remove_by_mountpoint(mountpoint);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            // On Windows, just proceed with net use /delete
            eprintln!("Note: Windows daemon mounts will be stopped via net use");
        }
    }

    eprintln!("Unmounting {}...", mountpoint.display());

    #[cfg(target_os = "macos")]
    {
        unmount_macos(mountpoint, args.force)?;
    }

    #[cfg(target_os = "linux")]
    {
        unmount_linux(mountpoint, args.force)?;
    }

    #[cfg(target_os = "windows")]
    {
        unmount_windows(mountpoint, args.force)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        anyhow::bail!("Unmount is not supported on this platform");
    }

    // Remove from state file after successful unmount
    if let Ok(manager) = MountStateManager::new() {
        let _ = manager.remove_by_mountpoint(mountpoint);
    }

    eprintln!("Unmounted successfully");
    Ok(())
}

/// Check if a path is still mounted (platform-specific).
#[allow(dead_code)]
fn is_still_mounted(mountpoint: &PathBuf) -> bool {
    if let Ok(system_mounts) = crate::state::get_system_mounts() {
        system_mounts.contains(mountpoint)
    } else {
        // If we can't check, assume it's still mounted
        true
    }
}

#[cfg(target_os = "macos")]
fn unmount_macos(mountpoint: &PathBuf, force: bool) -> Result<()> {
    // Try diskutil first (handles FUSE and FSKit)
    let mut cmd = Command::new("diskutil");
    cmd.arg("unmount");
    if force {
        cmd.arg("force");
    }
    cmd.arg(mountpoint);

    let output = cmd
        .output()
        .context("Failed to execute diskutil unmount")?;

    if output.status.success() {
        return Ok(());
    }

    // Fall back to umount
    let mut cmd = Command::new("umount");
    if force {
        cmd.arg("-f");
    }
    cmd.arg(mountpoint);

    let output = cmd
        .output()
        .context("Failed to execute umount")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to unmount: {}", stderr.trim());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn unmount_linux(mountpoint: &PathBuf, force: bool) -> Result<()> {
    // Try fusermount first (for FUSE mounts)
    let mut cmd = Command::new("fusermount");
    cmd.arg("-u");
    if force {
        cmd.arg("-z"); // lazy unmount
    }
    cmd.arg(mountpoint);

    let output = cmd.output();

    if let Ok(output) = output {
        if output.status.success() {
            return Ok(());
        }
    }

    // Fall back to umount
    let mut cmd = Command::new("umount");
    if force {
        cmd.arg("-l"); // lazy unmount
    }
    cmd.arg(mountpoint);

    let output = cmd
        .output()
        .context("Failed to execute umount")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to unmount: {}", stderr.trim());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn unmount_windows(mountpoint: &PathBuf, _force: bool) -> Result<()> {
    // On Windows, WebDAV mounts are typically mapped as network drives
    // Try `net use /delete` for network drives
    let mountpoint_str = mountpoint.to_string_lossy();

    // Check if it looks like a drive letter (e.g., "Z:" or "Z:\")
    if mountpoint_str.len() >= 2 && mountpoint_str.chars().nth(1) == Some(':') {
        let drive = &mountpoint_str[..2];
        let mut cmd = Command::new("net");
        cmd.args(["use", drive, "/delete", "/yes"]);

        let output = cmd.output().context("Failed to execute net use")?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // If it's not a network drive, the error is expected
        if !stderr.contains("network connection could not be found") {
            anyhow::bail!("Failed to unmount: {}", stderr.trim());
        }
    }

    // For non-drive paths or if net use failed, inform the user
    anyhow::bail!(
        "Cannot unmount {}: On Windows, unmount network drives via File Explorer or use 'net use X: /delete'",
        mountpoint.display()
    );
}
