//! Mount state persistence for crash recovery.
//!
//! Persists active mount information to a shared state file that's compatible
//! with the CLI's mount tracking. This allows:
//! - Recovery of mount state after GUI crash/restart
//! - Cleanup of orphaned mounts from either CLI or GUI
//!
//! State is persisted to `~/.config/oxcrypt/mounts.json` (same location as CLI).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
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
    /// Backend used (fuse, fileprovider, webdav, nfs)
    pub backend: String,
    /// Process ID of the mount process
    pub pid: u32,
    /// When the mount was started
    pub started_at: DateTime<Utc>,
    /// Whether this was a daemon mount (background)
    pub is_daemon: bool,
    /// Path to the IPC socket for this mount (if running as daemon)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
}

impl MountEntry {
    /// Create a new mount entry for a GUI mount (non-daemon).
    pub fn new_gui_mount(
        vault_path: PathBuf,
        mountpoint: PathBuf,
        backend: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vault_path,
            mountpoint,
            backend: backend.into(),
            pid: std::process::id(),
            started_at: Utc::now(),
            is_daemon: false, // GUI mounts are not daemons
            socket_path: None,
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

/// Manages the mount state file for the Desktop app.
pub struct DesktopMountState {
    state_path: PathBuf,
    lock_path: PathBuf,
}

/// Default timeout for acquiring the state file lock.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl DesktopMountState {
    /// Create a new state manager, initializing the config directory if needed.
    pub fn new() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("com", "oxcrypt", "oxcrypt")
            .context("Failed to determine config directory")?;
        let config_dir = dirs.config_dir();

        // Ensure config directory exists
        std::fs::create_dir_all(config_dir)
            .with_context(|| format!("Failed to create config dir: {}", config_dir.display()))?;

        let state_path = config_dir.join("mounts.json");
        let lock_path = config_dir.join("mounts.lock");

        Ok(Self {
            state_path,
            lock_path,
        })
    }

    /// Execute a function while holding an exclusive lock on the state file.
    fn with_lock<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut MountState) -> Result<R>,
    {
        // Create/open lock file
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_path)
            .with_context(|| format!("Failed to open lock file: {}", self.lock_path.display()))?;

        // Try to acquire lock with timeout
        let start = std::time::Instant::now();
        loop {
            match lock_file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > LOCK_TIMEOUT {
                        anyhow::bail!("Timed out waiting for state file lock");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to lock: {}", self.lock_path.display()))
                }
            }
        }

        // Load state
        let mut state = self.load_internal()?;
        let result = f(&mut state);

        // Save changes
        if let Err(e) = self.save_internal(&state) {
            tracing::warn!("Failed to save mount state: {}", e);
        }

        let _ = lock_file.unlock();
        result
    }

    fn load_internal(&self) -> Result<MountState> {
        if !self.state_path.exists() {
            return Ok(MountState::default());
        }

        let contents = std::fs::read_to_string(&self.state_path)
            .with_context(|| format!("Failed to read state file: {}", self.state_path.display()))?;

        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file: {}", self.state_path.display()))
    }

    fn save_internal(&self, state: &MountState) -> Result<()> {
        let contents = serde_json::to_string_pretty(state)?;
        std::fs::write(&self.state_path, contents)
            .with_context(|| format!("Failed to write state file: {}", self.state_path.display()))
    }

    /// Add a mount to the state file.
    pub fn add_mount(&self, entry: MountEntry) -> Result<()> {
        self.with_lock(|state| {
            // Remove any existing entry for the same mountpoint
            state
                .mounts
                .retain(|m| m.mountpoint != entry.mountpoint);
            state.mounts.push(entry);
            Ok(())
        })
    }

    /// Remove a mount from the state file by mountpoint.
    pub fn remove_mount(&self, mountpoint: &Path) -> Result<()> {
        let mountpoint = mountpoint.to_path_buf();
        self.with_lock(|state| {
            state.mounts.retain(|m| m.mountpoint != mountpoint);
            Ok(())
        })
    }

    /// Find active mounts for the current process.
    ///
    /// Returns mounts from the state file that:
    /// 1. Were created by this process (PID matches)
    /// 2. Are still mounted in the system
    ///
    /// This is used on startup to recover mount state after a crash.
    pub fn find_our_active_mounts(&self) -> Result<Vec<MountEntry>> {
        let state = self.load_internal()?;
        let system_mounts = get_system_mounts()?;
        let our_pid = std::process::id();

        let active: Vec<MountEntry> = state
            .mounts
            .into_iter()
            .filter(|m| {
                // Only our mounts
                if m.pid != our_pid {
                    return false;
                }
                // Must be in system mounts
                let canonical = m.mountpoint.canonicalize().unwrap_or_else(|_| m.mountpoint.clone());
                system_mounts.contains(&canonical)
            })
            .collect();

        Ok(active)
    }

    /// Find mounts for a specific vault path that are still active.
    ///
    /// Used to recover mount state on startup - checks if a vault we know about
    /// has an active mount from any process.
    pub fn find_active_mount_for_vault(&self, vault_path: &Path) -> Result<Option<MountEntry>> {
        let state = self.load_internal()?;
        let system_mounts = get_system_mounts()?;

        for entry in state.mounts {
            // Check if this entry is for our vault
            if entry.vault_path != vault_path {
                continue;
            }

            // Check if process is alive
            if !is_process_alive(entry.pid) {
                continue;
            }

            // Check if mount is in system
            let canonical = entry
                .mountpoint
                .canonicalize()
                .unwrap_or_else(|_| entry.mountpoint.clone());
            if system_mounts.contains(&canonical) {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Find orphaned mounts - entries where the process is dead but a mount may still exist.
    ///
    /// Returns mount entries that:
    /// 1. Have a dead process (PID no longer alive)
    /// 2. Optionally match one of the known vault paths
    ///
    /// Used on startup to clean up mounts from crashed sessions.
    pub fn find_orphaned_mounts(&self, known_vault_paths: &[PathBuf]) -> Result<Vec<MountEntry>> {
        let state = self.load_internal()?;

        let orphans: Vec<MountEntry> = state
            .mounts
            .into_iter()
            .filter(|m| {
                // Process must be dead
                if is_process_alive(m.pid) {
                    return false;
                }
                // If we have known vault paths, only include matching ones
                // Otherwise include all orphans
                known_vault_paths.is_empty()
                    || known_vault_paths.iter().any(|p| p == &m.vault_path)
            })
            .collect();

        Ok(orphans)
    }
}

/// Check if a process is alive.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    // SAFETY: PIDs are always positive and fit in i32 range on Unix systems
    #[allow(clippy::cast_possible_wrap)]
    kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    use std::process::Command;
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
    true
}

/// Get system mounts (canonicalized paths).
fn get_system_mounts() -> Result<std::collections::HashSet<PathBuf>> {
    let mut mounts = std::collections::HashSet::new();

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("mount")
            .output()
            .context("Failed to run mount command")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(on_idx) = line.find(" on ") {
                let rest = &line[on_idx + 4..];
                if let Some(paren_idx) = rest.find(" (") {
                    let path = PathBuf::from(&rest[..paren_idx]);
                    let canonical = path.canonicalize().unwrap_or(path);
                    mounts.insert(canonical);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let contents = std::fs::read_to_string("/proc/mounts")
            .context("Failed to read /proc/mounts")?;
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let path = PathBuf::from(parts[1]);
                let canonical = path.canonicalize().unwrap_or(path);
                mounts.insert(canonical);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("net")
            .args(["use"])
            .output()
            .context("Failed to run net use command")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
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
