//! Daemon utilities for spawning detached processes.
//!
//! This module provides utilities for spawning commands as daemons using `setsid()`.
//! The spawned process will:
//! - Be a session leader with no controlling terminal
//! - Have all standard streams redirected to /dev/null
//! - Be detached from the parent process
//!
//! Note: This uses a single-fork approach with setsid(), not the traditional
//! double-fork pattern. For most use cases (running a long-lived service),
//! this is sufficient.

use std::process::{Command, Stdio};

/// Spawn a command as a daemon using setsid().
///
/// This function:
/// - Redirects stdin/stdout/stderr to /dev/null
/// - Calls setsid() in the child to become session leader and process group leader
/// - Returns immediately with the child's PID (does not wait for completion)
///
/// The setsid() call creates a new session with the child as the session leader,
/// and also creates a new process group with the child as the process group leader.
/// This detaches the child from any controlling terminal.
///
/// # Arguments
///
/// * `command` - A mutable reference to the Command to spawn
///
/// # Returns
///
/// The PID of the spawned daemon process.
///
/// # Example
///
/// ```ignore
/// let mut cmd = Command::new("/usr/bin/my-daemon");
/// cmd.arg("--config").arg("/etc/my-daemon.conf");
/// let pid = spawn_as_daemon(&mut cmd)?;
/// println!("Daemon started with PID: {}", pid);
/// ```
#[cfg(unix)]
pub fn spawn_as_daemon(command: &mut Command) -> std::io::Result<u32> {
    use std::os::unix::process::CommandExt;

    // Redirect all streams to /dev/null
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());

    // Pre-exec hook to call setsid in child before exec
    // This makes the child a session leader with no controlling terminal
    // Note: setsid() creates both a new session AND a new process group,
    // so we don't need to call setpgid() separately via process_group().
    // In fact, calling process_group(0) would PREVENT setsid() from working
    // because setsid() requires that the calling process NOT be a process group leader.
    unsafe {
        command.pre_exec(|| {
            // Become session leader - this detaches from the controlling terminal
            // and makes this process the leader of a new session and process group
            match nix::unistd::setsid() {
                Ok(_) => Ok(()),
                Err(e) => Err(std::io::Error::from_raw_os_error(e as i32)),
            }
        });
    }

    let child = command.spawn()?;
    Ok(child.id())
}

/// Spawn a command as a daemon (non-Unix fallback).
///
/// On non-Unix platforms, this simply spawns the command with
/// streams redirected to null. No true daemonization is performed.
#[cfg(not(unix))]
pub fn spawn_as_daemon(command: &mut Command) -> std::io::Result<u32> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    let child = command.spawn()?;
    Ok(child.id())
}

/// Check if the current process is running as a daemon.
///
/// A process is considered a daemon if:
/// - It has no controlling terminal (Unix)
/// - Its parent is init (PID 1) or another system process
///
/// This is useful for adjusting behavior based on daemon vs foreground mode.
#[cfg(unix)]
pub fn is_daemon() -> bool {
    // Check if we have a controlling terminal by trying to open /dev/tty
    // A true daemon won't have a controlling terminal
    std::fs::File::open("/dev/tty").is_err()
}

#[cfg(not(unix))]
pub fn is_daemon() -> bool {
    // On non-Unix, we can't reliably detect daemon status
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_daemon_in_test() {
        // When running tests, we should have a controlling terminal
        // (unless tests are run in CI without a tty)
        let _ = is_daemon(); // Just ensure it doesn't panic
    }

    #[test]
    #[cfg(unix)]
    fn test_spawn_as_daemon_echo() {
        // Test that we can spawn a simple command as a daemon
        let mut cmd = Command::new("true"); // Simple command that exits 0
        let result = spawn_as_daemon(&mut cmd);
        assert!(result.is_ok());
        let pid = result.unwrap();
        assert!(pid > 0);

        // Give the process a moment to exit
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
