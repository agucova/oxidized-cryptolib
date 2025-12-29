//! Mount state management for tracking active daemon mounts.
//!
//! State is persisted to `~/.config/oxcrypt/mounts.json` (Linux/macOS)
//! or `%APPDATA%\oxidized\oxcrypt\mounts.json` (Windows).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single mount entry in the state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEntry {
    /// Unique identifier for this mount session
    pub id: String,
    /// Path to the vault directory
    pub vault_path: PathBuf,
    /// Where the vault is mounted
    pub mountpoint: PathBuf,
    /// Backend used (fuse, fskit, webdav, nfs)
    pub backend: String,
    /// Process ID of the mount process
    pub pid: u32,
    /// When the mount was started
    pub started_at: DateTime<Utc>,
    /// Whether this was a daemon mount (background)
    pub is_daemon: bool,
}

impl MountEntry {
    /// Create a new mount entry with auto-generated ID and current timestamp.
    pub fn new(
        vault_path: PathBuf,
        mountpoint: PathBuf,
        backend: impl Into<String>,
        pid: u32,
        is_daemon: bool,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vault_path,
            mountpoint,
            backend: backend.into(),
            pid,
            started_at: Utc::now(),
            is_daemon,
        }
    }
}

/// The complete mount state stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MountState {
    /// Schema version for future migrations
    #[serde(default = "default_version")]
    pub version: u32,
    /// Active mount entries
    #[serde(default)]
    pub mounts: Vec<MountEntry>,
}

fn default_version() -> u32 {
    1
}

/// Manages the mount state file.
pub struct MountStateManager {
    state_path: PathBuf,
}

impl MountStateManager {
    /// Create a new state manager, initializing the config directory if needed.
    pub fn new() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("com", "oxidized", "oxcrypt")
            .context("Failed to determine config directory")?;
        let config_dir = dirs.config_dir();

        // Ensure config directory exists
        std::fs::create_dir_all(config_dir)
            .with_context(|| format!("Failed to create config dir: {}", config_dir.display()))?;

        Ok(Self {
            state_path: config_dir.join("mounts.json"),
        })
    }

    /// Get the path to the state file.
    #[allow(dead_code)]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Load the current state, returning default if file doesn't exist.
    pub fn load(&self) -> Result<MountState> {
        if !self.state_path.exists() {
            return Ok(MountState::default());
        }

        let contents = std::fs::read_to_string(&self.state_path)
            .with_context(|| format!("Failed to read state file: {}", self.state_path.display()))?;

        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file: {}", self.state_path.display()))
    }

    /// Save the state to disk.
    pub fn save(&self, state: &MountState) -> Result<()> {
        let contents = serde_json::to_string_pretty(state)?;
        std::fs::write(&self.state_path, contents)
            .with_context(|| format!("Failed to write state file: {}", self.state_path.display()))
    }

    /// Add a new mount entry.
    pub fn add_mount(&self, entry: MountEntry) -> Result<()> {
        let mut state = self.load()?;

        // Remove any existing entry for the same mountpoint (stale)
        state
            .mounts
            .retain(|m| m.mountpoint != entry.mountpoint);

        state.mounts.push(entry);
        self.save(&state)
    }

    /// Remove a mount entry by ID.
    #[allow(dead_code)]
    pub fn remove_mount(&self, id: &str) -> Result<bool> {
        let mut state = self.load()?;
        let initial_len = state.mounts.len();
        state.mounts.retain(|m| m.id != id);
        let removed = state.mounts.len() != initial_len;
        if removed {
            self.save(&state)?;
        }
        Ok(removed)
    }

    /// Remove a mount entry by mountpoint path.
    pub fn remove_by_mountpoint(&self, mountpoint: &Path) -> Result<bool> {
        let mut state = self.load()?;
        let initial_len = state.mounts.len();
        state.mounts.retain(|m| m.mountpoint != mountpoint);
        let removed = state.mounts.len() != initial_len;
        if removed {
            self.save(&state)?;
        }
        Ok(removed)
    }

    /// Find a mount entry by mountpoint path.
    pub fn find_by_mountpoint(&self, mountpoint: &Path) -> Result<Option<MountEntry>> {
        let state = self.load()?;
        Ok(state.mounts.into_iter().find(|m| m.mountpoint == mountpoint))
    }

    /// Remove stale entries (process dead or not in system mounts).
    /// Returns the entries that were removed.
    pub fn cleanup_stale(&self) -> Result<Vec<MountEntry>> {
        let mut state = self.load()?;
        let system_mounts = get_system_mounts()?;

        let mut stale = Vec::new();
        let mut active = Vec::new();

        for entry in state.mounts {
            let pid_alive = is_process_alive(entry.pid);
            let in_system = system_mounts.contains(&entry.mountpoint);

            if pid_alive && in_system {
                active.push(entry);
            } else {
                stale.push(entry);
            }
        }

        if !stale.is_empty() {
            state.mounts = active;
            self.save(&state)?;
        }

        Ok(stale)
    }

    /// Validate entries and partition into active vs stale.
    pub fn validate_entries(&self) -> Result<(Vec<MountEntry>, Vec<MountEntry>)> {
        let state = self.load()?;
        let system_mounts = get_system_mounts()?;

        let mut active = Vec::new();
        let mut stale = Vec::new();

        for entry in state.mounts {
            let pid_alive = is_process_alive(entry.pid);
            let in_system = system_mounts.contains(&entry.mountpoint);

            if pid_alive && in_system {
                active.push(entry);
            } else {
                stale.push(entry);
            }
        }

        Ok((active, stale))
    }
}

/// Check if a process with the given PID is alive.
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
    // On Windows, try to open the process with minimal permissions
    // If it fails, the process doesn't exist or we can't access it
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
    // Assume alive on unsupported platforms
    true
}

/// Get the set of currently mounted filesystem paths.
pub fn get_system_mounts() -> Result<std::collections::HashSet<PathBuf>> {
    let mut mounts = std::collections::HashSet::new();

    #[cfg(target_os = "linux")]
    {
        // Parse /proc/mounts
        let contents = std::fs::read_to_string("/proc/mounts")
            .context("Failed to read /proc/mounts")?;
        for line in contents.lines() {
            // Format: device mountpoint fstype options dump pass
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                mounts.insert(PathBuf::from(parts[1]));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Run `mount` command and parse output
        let output = std::process::Command::new("mount")
            .output()
            .context("Failed to run mount command")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Format: /dev/disk1s1 on /path (type, options)
            if let Some(on_idx) = line.find(" on ") {
                let rest = &line[on_idx + 4..];
                if let Some(paren_idx) = rest.find(" (") {
                    mounts.insert(PathBuf::from(&rest[..paren_idx]));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Parse `net use` for network drives
        let output = std::process::Command::new("net")
            .args(["use"])
            .output()
            .context("Failed to run net use command")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Look for drive letters like "OK           Z:        \\server\share"
            let parts: Vec<&str> = line.split_whitespace().collect();
            for part in parts {
                if part.len() == 2 && part.ends_with(':') {
                    mounts.insert(PathBuf::from(part));
                }
            }
        }
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_entry_creation() {
        let entry = MountEntry::new(
            PathBuf::from("/home/user/vault"),
            PathBuf::from("/mnt/vault"),
            "fuse",
            12345,
            true,
        );
        assert!(!entry.id.is_empty());
        assert_eq!(entry.backend, "fuse");
        assert_eq!(entry.pid, 12345);
        assert!(entry.is_daemon);
    }

    #[test]
    fn test_state_serialization() {
        let mut state = MountState::default();
        state.mounts.push(MountEntry::new(
            PathBuf::from("/vault"),
            PathBuf::from("/mnt"),
            "fuse",
            1234,
            false,
        ));

        let json = serde_json::to_string(&state).unwrap();
        let loaded: MountState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.mounts.len(), 1);
        assert_eq!(loaded.mounts[0].backend, "fuse");
    }

    #[test]
    fn test_is_process_alive() {
        // Current process should be alive
        let pid = std::process::id();
        assert!(is_process_alive(pid));

        // Very high PID should not exist
        assert!(!is_process_alive(u32::MAX - 1));
    }
}
