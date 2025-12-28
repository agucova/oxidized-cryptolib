//! Unmount command - unmount a previously mounted Cryptomator vault.
//!
//! Uses platform-specific tools:
//! - macOS: `umount` or `diskutil unmount`
//! - Linux: `fusermount -u` or `umount`

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;
use std::process::Command;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Directory where the vault is mounted
    pub mountpoint: PathBuf,

    /// Force unmount even if the filesystem is busy
    #[arg(short, long)]
    pub force: bool,
}

pub fn execute(args: Args) -> Result<()> {
    let mountpoint = &args.mountpoint;

    // Check if mountpoint exists
    if !mountpoint.exists() {
        anyhow::bail!("Mountpoint does not exist: {}", mountpoint.display());
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

    eprintln!("Unmounted successfully");
    Ok(())
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
