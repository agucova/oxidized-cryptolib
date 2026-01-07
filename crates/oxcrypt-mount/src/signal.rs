//! Simple signal handling using signal-hook.
//!
//! Provides graceful shutdown with double Ctrl+C support:
//! - First signal: Sets shutdown flag, allows cleanup
//! - Second signal: Immediate process exit
//!
//! Handles SIGINT, SIGTERM, and SIGHUP (terminal hangup).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::flag;

#[cfg(unix)]
use signal_hook::consts::signal::SIGHUP;

/// Global shutdown flag
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Tracks if handler has been installed
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Condvar for blocking wait on shutdown
static SHUTDOWN_CONDVAR: std::sync::OnceLock<(Mutex<bool>, Condvar)> = std::sync::OnceLock::new();

/// Get or initialize the shutdown condvar
fn shutdown_condvar() -> &'static (Mutex<bool>, Condvar) {
    SHUTDOWN_CONDVAR.get_or_init(|| (Mutex::new(false), Condvar::new()))
}

/// Install signal handlers for graceful shutdown.
///
/// Handles SIGINT (Ctrl+C), SIGTERM, and SIGHUP (terminal hangup):
/// - First signal: Sets shutdown flag, allows cleanup
/// - Second signal: Immediately exits (via register_conditional_shutdown)
///
/// Safe to call multiple times; subsequent calls are no-ops.
pub fn install_signal_handler() -> Result<(), std::io::Error> {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(()); // Already installed
    }

    // Arc-based flag for signal-hook
    let shutdown = Arc::new(AtomicBool::new(false));

    // Register TERM_SIGNALS (SIGINT, SIGTERM)
    for &sig in TERM_SIGNALS {
        // Second signal terminates immediately if shutdown already requested
        flag::register_conditional_shutdown(sig, 1, Arc::clone(&shutdown))?;
        // First signal sets the flag
        flag::register(sig, Arc::clone(&shutdown))?;
    }

    // Also handle SIGHUP (terminal hangup) on Unix
    #[cfg(unix)]
    {
        flag::register_conditional_shutdown(SIGHUP, 1, Arc::clone(&shutdown))?;
        flag::register(SIGHUP, Arc::clone(&shutdown))?;
    }

    // Initialize condvar
    let (lock, cvar) = shutdown_condvar();

    // Monitor thread syncs Arc flag to our static and notifies waiters
    let shutdown_clone = Arc::clone(&shutdown);
    std::thread::spawn(move || {
        while !shutdown_clone.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
        }
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);

        // Notify any threads waiting on shutdown
        {
            let mut guard = lock.lock();
            *guard = true;
            cvar.notify_all();
        }

        eprintln!("\nShutdown requested (Ctrl+C again to force exit)");
    });

    Ok(())
}

/// Check if shutdown was requested.
///
/// Poll this in long-running operations to detect interruption.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Wait for shutdown signal, blocking the current thread.
///
/// This is more efficient than polling `shutdown_requested()` in a loop
/// as it uses a condvar to sleep until a signal arrives.
///
/// Returns immediately if shutdown was already requested.
pub fn wait_for_shutdown() {
    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        return;
    }

    let (lock, cvar) = shutdown_condvar();
    let mut guard = lock.lock();

    // Double-check after acquiring lock
    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        return;
    }

    // Wait until notified
    cvar.wait(&mut guard);
}

/// Wait for shutdown signal with timeout.
///
/// Returns `true` if shutdown was requested, `false` if timeout expired.
/// This is useful for periodic work that should also respond to shutdown.
pub fn wait_for_shutdown_timeout(timeout: Duration) -> bool {
    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        return true;
    }

    let (lock, cvar) = shutdown_condvar();
    let mut guard = lock.lock();

    // Double-check after acquiring lock
    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        return true;
    }

    // Wait with timeout
    let result = cvar.wait_for(&mut guard, timeout);

    // Return whether we were signaled (not timed out)
    !result.timed_out() || SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Clear shutdown state.
///
/// Useful for testing or resetting state between operations.
pub fn clear_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);

    // Also reset the condvar state
    let (lock, _cvar) = shutdown_condvar();
    let mut guard = lock.lock();
    *guard = false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_handler_idempotent() {
        // Should be safe to call multiple times
        let _result1 = install_signal_handler();
        let result2 = install_signal_handler();

        // Second should always return Ok (already installed check)
        assert!(result2.is_ok());
    }

    #[test]
    fn test_shutdown_flag() {
        // Initially should be false
        clear_shutdown();
        assert!(!shutdown_requested());

        // Can be set manually
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        assert!(shutdown_requested());

        // Can be cleared
        clear_shutdown();
        assert!(!shutdown_requested());
    }
}
