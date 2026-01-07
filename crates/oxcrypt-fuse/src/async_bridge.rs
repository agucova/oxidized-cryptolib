//! Bridge between sync FUSE callbacks and async vault operations.
//!
//! This module provides a minimal interface to execute async operations from
//! synchronous FUSE callback threads. It uses a simple spawn+oneshot pattern
//! to avoid stack overflow issues while maintaining timeout protection and
//! observability through statistics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

/// Statistics for async bridge operations (for observability).
#[derive(Debug, Default)]
pub struct BridgeStats {
    pub operations_started: AtomicU64,
    pub operations_completed: AtomicU64,
    pub operations_timed_out: AtomicU64,
}

impl BridgeStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_start(&self) {
        self.operations_started.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_complete(&self) {
        self.operations_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.operations_timed_out.fetch_add(1, Ordering::Relaxed);
    }
}

/// Error from async bridge operations
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    #[error("operation was cancelled")]
    Cancelled,
}

impl BridgeError {
    pub fn to_errno(&self) -> i32 {
        match self {
            BridgeError::Timeout(_) => libc::ETIMEDOUT,
            BridgeError::Cancelled => libc::ECANCELED,
        }
    }
}

/// Execute an async future from sync context with timeout.
///
/// Spawns the future on the tokio runtime and blocks the calling thread
/// on a oneshot channel until completion or timeout.
///
/// IMPORTANT: If the operation times out, the spawned task is aborted to
/// prevent zombie tasks from holding locks or other resources.
///
/// # Arguments
///
/// * `handle` - Tokio runtime handle to spawn the future on
/// * `timeout` - Maximum duration to wait for the operation
/// * `stats` - Optional statistics tracker
/// * `future` - The async operation to execute
///
/// # Returns
///
/// * `Ok(T)` - The result of the async operation
/// * `Err(BridgeError::Timeout)` - Operation timed out
/// * `Err(BridgeError::Cancelled)` - Operation was cancelled
pub fn execute<F, T>(
    handle: &Handle,
    timeout: Duration,
    stats: Option<&BridgeStats>,
    future: F,
) -> Result<T, BridgeError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if let Some(s) = stats {
        s.record_start();
    }

    let (tx, rx) = oneshot::channel();

    // Spawn the task and keep the handle so we can abort on timeout
    let task_handle = handle.spawn(async move {
        let result = tokio::time::timeout(timeout, future).await;
        // Ignore send error - receiver may have timed out
        let _ = tx.send(result);
    });

    match rx.blocking_recv() {
        Ok(Ok(value)) => {
            if let Some(s) = stats {
                s.record_complete();
            }
            Ok(value)
        }
        Ok(Err(_elapsed)) => {
            // Timeout occurred - abort the task to release any held locks/resources
            task_handle.abort();
            if let Some(s) = stats {
                s.record_timeout();
            }
            Err(BridgeError::Timeout(timeout))
        }
        Err(_recv_error) => {
            // Channel was closed - abort the task to clean up
            task_handle.abort();
            Err(BridgeError::Cancelled)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_simple() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = execute(rt.handle(), Duration::from_secs(5), None, async { 42 });
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_timeout() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = execute(
            rt.handle(),
            Duration::from_millis(10),
            None,
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                42
            },
        );
        assert!(matches!(result, Err(BridgeError::Timeout(_))));
    }

    #[test]
    fn test_stats_tracking() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stats = BridgeStats::new();
        let _ = execute(rt.handle(), Duration::from_secs(5), Some(&stats), async {
            42
        });
        assert_eq!(stats.operations_started.load(Ordering::Relaxed), 1);
        assert_eq!(stats.operations_completed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stats_timeout() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stats = BridgeStats::new();
        let _ = execute(
            rt.handle(),
            Duration::from_millis(10),
            Some(&stats),
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                42
            },
        );
        assert_eq!(stats.operations_started.load(Ordering::Relaxed), 1);
        assert_eq!(stats.operations_timed_out.load(Ordering::Relaxed), 1);
        assert_eq!(stats.operations_completed.load(Ordering::Relaxed), 0);
    }
}
