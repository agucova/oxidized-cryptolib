//! Process detection utilities for mount operations
//!
//! Provides functionality to detect which processes are using files
//! within a mounted filesystem. Useful for showing users what's blocking
//! an unmount operation.

use std::path::Path;

/// Information about a process using a file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (command)
    pub name: String,
    /// File path being accessed (if available)
    pub file_path: Option<String>,
}

/// Find processes using files under a mountpoint
///
/// Uses `lsof` on macOS and Linux to detect open file handles.
/// Returns an empty vector on unsupported platforms or if detection fails.
///
/// # Arguments
///
/// * `mountpoint` - The mount point to check for open files
///
/// # Example
///
/// ```ignore
/// let procs = find_processes_using_mount(Path::new("/Volumes/MyVault"));
/// for proc in procs {
///     println!("{} (PID {}) is using the vault", proc.name, proc.pid);
/// }
/// ```
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn find_processes_using_mount(mountpoint: &Path) -> Vec<ProcessInfo> {
    use std::collections::HashMap;
    use std::process::Command;

    let output = match Command::new("lsof")
        .arg("+D")
        .arg(mountpoint)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            tracing::debug!("Failed to run lsof: {}", e);
            return Vec::new();
        }
    };

    if !output.status.success() && output.stdout.is_empty() {
        // lsof returns non-zero if no files are found, which is fine
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes: HashMap<u32, ProcessInfo> = HashMap::new();

    // Skip header line, parse each subsequent line
    // lsof output format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let name = parts[0].to_string();
        let pid: u32 = match parts[1].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // The file path is the last column (NAME)
        let file_path = parts.last().map(ToString::to_string);

        // Deduplicate by PID, keeping first occurrence
        processes.entry(pid).or_insert(ProcessInfo {
            pid,
            name,
            file_path,
        });
    }

    processes.into_values().collect()
}

/// Stub implementation for unsupported platforms
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn find_processes_using_mount(_mountpoint: &Path) -> Vec<ProcessInfo> {
    // lsof is not available on Windows or other platforms
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info_equality() {
        let p1 = ProcessInfo {
            pid: 123,
            name: "test".to_string(),
            file_path: Some("/path".to_string()),
        };
        let p2 = ProcessInfo {
            pid: 123,
            name: "test".to_string(),
            file_path: Some("/path".to_string()),
        };
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_find_processes_nonexistent_path() {
        // Should return empty, not panic
        let procs = find_processes_using_mount(Path::new("/nonexistent/path/12345"));
        assert!(procs.is_empty());
    }
}
