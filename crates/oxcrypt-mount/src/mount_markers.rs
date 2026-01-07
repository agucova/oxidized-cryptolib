//! Mount marker identification for detecting oxcrypt-core mounts.
//!
//! This module provides utilities to identify FUSE mounts that belong to
//! oxcrypt-core versus mounts from other programs. This is critical
//! for safety: we must never accidentally unmount foreign mounts.
//!
//! # Mount Markers
//!
//! Our mounts use these identifiers:
//! - FSName: `cryptomator:{vault_id}` or `cryptomator-test` (for tests)
//! - Subtype: `oxcrypt` (Linux shows this as `fuse.oxcrypt`)
//!
//! # Platform Differences
//!
//! - **macOS**: Parse `mount` command output for `macfuse` type
//! - **Linux**: Parse `/proc/mounts` for `fuse` or `fuse.oxcrypt` type

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Information about a system mount with full metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemMount {
    /// The mount point path (e.g., `/Users/me/Vaults/myvault`)
    pub mountpoint: PathBuf,
    /// The filesystem type (e.g., `macfuse`, `fuse`, `fuse.oxcrypt`)
    pub fstype: String,
    /// The filesystem name / device (e.g., `cryptomator:myvault`)
    pub fsname: String,
}

/// Our mount marker patterns.
///
/// FSName patterns that identify a mount as belonging to oxcrypt-core:
/// - `cryptomator:{vault_id}` - production mounts
/// - `cryptomator-test` - test mounts
/// - `cryptomator` - legacy/simple mounts
const FSNAME_PREFIXES: &[&str] = &["cryptomator:", "cryptomator-test", "cryptomator"];

/// Filesystem types that indicate FUSE mounts on various platforms.
#[cfg(target_os = "macos")]
const FUSE_FSTYPES: &[&str] = &["macfuse", "osxfuse", "fuse"];

#[cfg(target_os = "linux")]
const FUSE_FSTYPES: &[&str] = &["fuse", "fuse.oxcrypt", "fuseblk"];

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const FUSE_FSTYPES: &[&str] = &[];

/// Check if a mount belongs to oxcrypt-core based on its markers.
///
/// Returns `true` if:
/// - The mount's fsname matches one of our FUSE patterns:
///   - Starts with `cryptomator:`
///   - Equals `cryptomator-test`
///   - Equals `cryptomator`
/// - OR the mount is a WebDAV mount (fstype = "webdav")
///   - Note: WebDAV mounts can't have custom fsnames, so we identify them by fstype
///   - The state file + process check provides the safety verification
///
/// # Safety
///
/// This is the primary safety check to avoid unmounting foreign mounts.
/// Only mounts that return `true` from this function should ever be
/// considered for cleanup operations.
pub fn is_our_mount(mount: &SystemMount) -> bool {
    let fsname_lower = mount.fsname.to_lowercase();
    let fstype_lower = mount.fstype.to_lowercase();

    // Check for our FUSE mount markers
    for prefix in FSNAME_PREFIXES {
        if fsname_lower.starts_with(prefix) || fsname_lower == *prefix {
            return true;
        }
    }

    // WebDAV mounts don't support custom fsnames in the mount table,
    // so we identify them by fstype. The state file provides additional
    // verification that we own the mount (via PID and socket path).
    if fstype_lower == "webdav" {
        return true;
    }

    // NFS mounts also don't support custom fsnames - identify by localhost + port pattern
    // Our NFS server runs on localhost with a high port number
    if fstype_lower == "nfs" && fsname_lower.starts_with("127.0.0.1:") {
        return true;
    }

    false
}

/// Check if a filesystem type indicates a FUSE mount.
pub fn is_fuse_fstype(fstype: &str) -> bool {
    let fstype_lower = fstype.to_lowercase();
    FUSE_FSTYPES
        .iter()
        .any(|ft| fstype_lower == *ft || fstype_lower.starts_with(&format!("{ft}.")))
}

/// Get all system mounts with detailed metadata.
///
/// Parses platform-specific mount information to return a list of all
/// currently mounted filesystems with their type and name.
pub fn get_system_mounts_detailed() -> Result<Vec<SystemMount>> {
    #[cfg(target_os = "macos")]
    {
        get_system_mounts_macos()
    }

    #[cfg(target_os = "linux")]
    {
        get_system_mounts_linux()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // Unsupported platform - return empty list
        Ok(Vec::new())
    }
}

/// Find all oxcrypt-core mounts on the system.
///
/// Filters system mounts to return only those that match our markers.
pub fn find_our_mounts() -> Result<Vec<SystemMount>> {
    let all_mounts = get_system_mounts_detailed()?;
    Ok(all_mounts.into_iter().filter(is_our_mount).collect())
}

/// Find all FUSE mounts on the system (ours and foreign).
pub fn find_fuse_mounts() -> Result<Vec<SystemMount>> {
    let all_mounts = get_system_mounts_detailed()?;
    Ok(all_mounts
        .into_iter()
        .filter(|m| is_fuse_fstype(&m.fstype))
        .collect())
}

// ============================================================================
// Platform-specific implementations
// ============================================================================

/// Timeout for mount command execution.
/// Ghost mounts can cause the mount command to block indefinitely.
/// Keep this short (1s) since the mount command should respond instantly on healthy systems.
#[cfg(target_os = "macos")]
const MOUNT_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Parse macOS mount output.
///
/// Format: `{fsname} on {mountpoint} ({fstype}, {options...})`
/// Example: `cryptomator:myvault on /Users/me/vault (macfuse, nodev, nosuid)`
///
/// Uses timeout protection because the `mount` command can block indefinitely
/// when ghost FUSE mounts exist in the system. Note that `mount` uses stdio
/// buffering, so when it blocks on a ghost mount, buffered output isn't flushed
/// even though some lines have been written. We kill the process on timeout
/// and return an empty list with a warning.
#[cfg(target_os = "macos")]
fn get_system_mounts_macos() -> Result<Vec<SystemMount>> {
    use std::sync::mpsc;

    // Spawn the mount command with stdin from /dev/null
    let child = std::process::Command::new("mount")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn mount command")?;

    // Use a channel to wait for the command with a timeout
    let (tx, rx) = mpsc::channel();
    let child_id = child.id();

    std::thread::spawn(move || {
        let result = child.wait_with_output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(MOUNT_COMMAND_TIMEOUT) {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut mounts = Vec::new();

            for line in stdout.lines() {
                if let Some(mount) = parse_macos_mount_line(line) {
                    mounts.push(mount);
                }
            }

            Ok(mounts)
        }
        Ok(Err(e)) => Err(anyhow::anyhow!("Mount command failed: {e}")),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Kill the process - unlike threads, subprocesses can be killed
            #[cfg(unix)]
            unsafe {
                // child_id is u32 (from Child::id()), cast to i32 for libc::kill
                libc::kill(i32::try_from(child_id).unwrap_or(-1), libc::SIGKILL);
            }
            // Return empty list with warning - allows cleanup operations to continue
            // even when ghost mounts are blocking the mount command
            tracing::warn!(
                "Mount command timed out after {:?} - possible ghost mounts blocking. \
                 Returning empty mount list.",
                MOUNT_COMMAND_TIMEOUT
            );
            Ok(Vec::new())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            tracing::warn!("Mount command thread terminated unexpectedly. Returning empty mount list.");
            Ok(Vec::new())
        }
    }
}

#[cfg(target_os = "macos")]
fn parse_macos_mount_line(line: &str) -> Option<SystemMount> {
    // Format: "{fsname} on {mountpoint} ({fstype}, {options...})"
    let on_idx = line.find(" on ")?;
    let fsname = line[..on_idx].to_string();

    let rest = &line[on_idx + 4..];
    let paren_idx = rest.find(" (")?;
    let mountpoint = PathBuf::from(&rest[..paren_idx]);

    // Extract fstype from parentheses
    let opts_start = rest.find('(')? + 1;
    let opts_end = rest.find(')')?;
    let opts = &rest[opts_start..opts_end];

    // First option is usually the fstype
    let fstype = opts.split(',').next()?.trim().to_string();

    Some(SystemMount {
        mountpoint,
        fstype,
        fsname,
    })
}

/// Parse Linux /proc/mounts.
///
/// Format: `{device} {mountpoint} {fstype} {options} {dump} {pass}`
/// Example: `cryptomator:vault /mnt/vault fuse.oxcrypt rw,nosuid 0 0`
#[cfg(target_os = "linux")]
fn get_system_mounts_linux() -> Result<Vec<SystemMount>> {
    let contents =
        std::fs::read_to_string("/proc/mounts").context("Failed to read /proc/mounts")?;

    let mut mounts = Vec::new();

    for line in contents.lines() {
        if let Some(mount) = parse_linux_mount_line(line) {
            mounts.push(mount);
        }
    }

    Ok(mounts)
}

#[cfg(target_os = "linux")]
fn parse_linux_mount_line(line: &str) -> Option<SystemMount> {
    // Format: "{device} {mountpoint} {fstype} {options} {dump} {pass}"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let fsname = parts[0].to_string();
    let mountpoint = PathBuf::from(unescape_mount_path(parts[1]));
    let fstype = parts[2].to_string();

    Some(SystemMount {
        mountpoint,
        fstype,
        fsname,
    })
}

/// Unescape special characters in mount paths from /proc/mounts.
///
/// /proc/mounts uses octal escapes for special characters:
/// - `\040` = space
/// - `\011` = tab
/// - `\012` = newline
/// - `\134` = backslash
#[cfg(target_os = "linux")]
fn unescape_mount_path(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            // Try to read 3 octal digits
            let mut octal = String::with_capacity(3);
            for _ in 0..3 {
                if let Some(&next) = chars.peek() {
                    if next.is_ascii_digit() && next < '8' {
                        octal.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
            }

            if octal.len() == 3 {
                if let Ok(code) = u8::from_str_radix(&octal, 8) {
                    result.push(code as char);
                    continue;
                }
            }

            // Not a valid escape, keep the backslash and digits
            result.push('\\');
            result.push_str(&octal);
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_our_mount_cryptomator_prefix() {
        let mount = SystemMount {
            mountpoint: PathBuf::from("/mnt/vault"),
            fstype: "macfuse".to_string(),
            fsname: "cryptomator:myvault".to_string(),
        };
        assert!(is_our_mount(&mount));
    }

    #[test]
    fn test_is_our_mount_cryptomator_test() {
        let mount = SystemMount {
            mountpoint: PathBuf::from("/tmp/test"),
            fstype: "fuse".to_string(),
            fsname: "cryptomator-test".to_string(),
        };
        assert!(is_our_mount(&mount));
    }

    #[test]
    fn test_is_our_mount_simple_cryptomator() {
        let mount = SystemMount {
            mountpoint: PathBuf::from("/mnt/vault"),
            fstype: "fuse.oxcrypt".to_string(),
            fsname: "cryptomator".to_string(),
        };
        assert!(is_our_mount(&mount));
    }

    #[test]
    fn test_is_our_mount_foreign() {
        let mount = SystemMount {
            mountpoint: PathBuf::from("/mnt/sshfs"),
            fstype: "fuse.sshfs".to_string(),
            fsname: "user@host:/path".to_string(),
        };
        assert!(!is_our_mount(&mount));
    }

    #[test]
    fn test_is_our_mount_case_insensitive() {
        let mount = SystemMount {
            mountpoint: PathBuf::from("/mnt/vault"),
            fstype: "macfuse".to_string(),
            fsname: "Cryptomator:MyVault".to_string(),
        };
        assert!(is_our_mount(&mount));
    }

    #[test]
    fn test_is_fuse_fstype() {
        assert!(is_fuse_fstype("fuse"));
        assert!(is_fuse_fstype("fuse.oxcrypt"));
        assert!(is_fuse_fstype("FUSE"));
        #[cfg(target_os = "macos")]
        {
            assert!(is_fuse_fstype("macfuse"));
            assert!(is_fuse_fstype("osxfuse"));
        }
        assert!(!is_fuse_fstype("ext4"));
        assert!(!is_fuse_fstype("apfs"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_macos_mount_line() {
        let line = "cryptomator:myvault on /Users/me/Vaults/myvault (macfuse, nodev, nosuid)";
        let mount = parse_macos_mount_line(line).unwrap();

        assert_eq!(mount.fsname, "cryptomator:myvault");
        assert_eq!(mount.mountpoint, PathBuf::from("/Users/me/Vaults/myvault"));
        assert_eq!(mount.fstype, "macfuse");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_macos_mount_line_with_spaces() {
        let line =
            "cryptomator:vault on /Users/me/My Vaults/my vault (macfuse, nodev, nosuid)";
        let mount = parse_macos_mount_line(line).unwrap();

        assert_eq!(mount.mountpoint, PathBuf::from("/Users/me/My Vaults/my vault"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_linux_mount_line() {
        let line = "cryptomator:vault /mnt/vault fuse.oxcrypt rw,nosuid,nodev 0 0";
        let mount = parse_linux_mount_line(line).unwrap();

        assert_eq!(mount.fsname, "cryptomator:vault");
        assert_eq!(mount.mountpoint, PathBuf::from("/mnt/vault"));
        assert_eq!(mount.fstype, "fuse.oxcrypt");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_unescape_mount_path() {
        // \040 = space
        assert_eq!(unescape_mount_path("/mnt/my\\040vault"), "/mnt/my vault");
        // Multiple escapes
        assert_eq!(
            unescape_mount_path("/mnt/a\\040b\\040c"),
            "/mnt/a b c"
        );
        // No escapes
        assert_eq!(unescape_mount_path("/mnt/vault"), "/mnt/vault");
    }
}
