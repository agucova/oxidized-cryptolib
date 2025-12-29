//! Mount configuration for the FUSE filesystem.
//!
//! This module provides configuration options for tuning the filesystem
//! behavior, particularly for different storage backends (local vs network).

use oxcrypt_mount::{
    DEFAULT_NEGATIVE_TTL, DEFAULT_TTL, LOCAL_NEGATIVE_TTL, LOCAL_TTL,
};
use std::time::Duration;

/// Default I/O timeout for network backends (30 seconds).
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// I/O timeout for local backends (10 seconds).
pub const LOCAL_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum number of I/O worker threads.
pub const MIN_IO_WORKERS: usize = 16;

/// Returns the default number of I/O worker threads based on CPU count.
///
/// I/O workers spend most of their time waiting for network/storage, not
/// using CPU. We use a baseline of 16 workers to handle typical cloud
/// storage concurrency (where operations can take 30+ seconds), scaling
/// up on machines with more cores.
///
/// For very slow storage backends, consider increasing further via
/// [`MountConfig::io_workers()`].
pub fn default_io_workers() -> usize {
    num_cpus::get().saturating_mul(2).max(MIN_IO_WORKERS)
}

/// Policy for handling executor queue saturation.
///
/// When all I/O workers are busy and the queue is full, this policy
/// determines how new operations are handled. Each option has trade-offs:
///
/// - [`Block`](SaturationPolicy::Block): Safe but slow - blocks the FUSE thread
/// - [`ReturnBusy`](SaturationPolicy::ReturnBusy): Fast but some apps handle EAGAIN poorly
/// - [`WaitThenError`](SaturationPolicy::WaitThenError): Compromise - brief wait, then error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaturationPolicy {
    /// Block the FUSE thread until a worker becomes available.
    ///
    /// This is the safest option - operations always complete eventually.
    /// However, it defeats the purpose of the async executor under heavy load,
    /// as the FUSE thread becomes blocked anyway.
    ///
    /// Use this for maximum compatibility with applications that don't
    /// handle transient errors well.
    Block,

    /// Return EAGAIN immediately, letting the kernel retry.
    ///
    /// This keeps the FUSE thread responsive but some applications
    /// (especially older ones) may not handle EAGAIN gracefully and
    /// could report spurious errors to users.
    ///
    /// Use this for maximum responsiveness when you know your applications
    /// handle retries correctly.
    ReturnBusy,

    /// Wait briefly for a slot, then return EIO if still saturated.
    ///
    /// A compromise: gives operations a chance to complete quickly,
    /// but doesn't block indefinitely. The wait duration should be
    /// short (100-500ms) to maintain responsiveness.
    ///
    /// This is the default - it handles brief load spikes gracefully
    /// while failing fast under sustained overload.
    WaitThenError(Duration),
}

impl Default for SaturationPolicy {
    fn default() -> Self {
        // Brief wait (250ms) before failing - handles load spikes
        SaturationPolicy::WaitThenError(Duration::from_millis(250))
    }
}

/// Configuration options for the FUSE filesystem.
///
/// Default configuration is optimized for network filesystems (Google Drive,
/// Dropbox, etc.) with longer cache TTLs. Use [`MountConfig::local()`] for
/// local filesystem vaults with shorter TTLs for fresher metadata.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Time-to-live for cached file attributes.
    ///
    /// Default: 60 seconds (network mode) or 1 second (local mode).
    pub attr_ttl: Duration,

    /// Time-to-live for negative cache entries (ENOENT).
    ///
    /// Default: 30 seconds (network mode) or 500ms (local mode).
    pub negative_ttl: Duration,

    /// Maximum concurrent I/O operations for directory listings.
    ///
    /// Higher values improve throughput on high-latency backends but
    /// may overwhelm rate-limited services. Default: 32.
    pub concurrency_limit: usize,

    /// Timeout for individual I/O operations.
    ///
    /// Operations that exceed this timeout will fail with ETIMEDOUT.
    /// This prevents slow cloud storage from blocking the entire filesystem.
    /// Default: 30 seconds (network mode) or 10 seconds (local mode).
    pub io_timeout: Duration,

    /// Number of dedicated I/O worker threads.
    ///
    /// These threads handle async operations without blocking FUSE.
    /// Higher values allow more concurrent slow operations.
    /// Default: 2x CPU cores, minimum 8. See [`default_io_workers()`].
    pub io_workers: usize,

    /// Policy for handling executor queue saturation.
    ///
    /// Determines behavior when all I/O workers are busy and the queue
    /// is full. See [`SaturationPolicy`] for options and trade-offs.
    /// Default: [`SaturationPolicy::WaitThenError`] with 250ms wait.
    pub saturation_policy: SaturationPolicy,
}

impl Default for MountConfig {
    /// Returns the default configuration optimized for network filesystems.
    fn default() -> Self {
        Self {
            attr_ttl: DEFAULT_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            concurrency_limit: 32,
            io_timeout: DEFAULT_IO_TIMEOUT,
            io_workers: default_io_workers(),
            saturation_policy: SaturationPolicy::default(),
        }
    }
}

impl MountConfig {
    /// Creates a configuration optimized for local filesystem vaults.
    ///
    /// Uses shorter cache TTLs (1s / 500ms) for fresher metadata
    /// and shorter I/O timeout.
    pub fn local() -> Self {
        Self {
            attr_ttl: LOCAL_TTL,
            negative_ttl: LOCAL_NEGATIVE_TTL,
            concurrency_limit: 32,
            io_timeout: LOCAL_IO_TIMEOUT,
            io_workers: default_io_workers(),
            saturation_policy: SaturationPolicy::default(),
        }
    }

    /// Creates a configuration with custom TTL values.
    pub fn with_ttl(attr_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            attr_ttl,
            negative_ttl,
            ..Default::default()
        }
    }

    /// Sets the cache TTL for file attributes.
    #[must_use]
    pub fn attr_ttl(mut self, ttl: Duration) -> Self {
        self.attr_ttl = ttl;
        self
    }

    /// Sets the cache TTL for negative entries.
    #[must_use]
    pub fn negative_ttl(mut self, ttl: Duration) -> Self {
        self.negative_ttl = ttl;
        self
    }

    /// Sets the concurrency limit for directory operations.
    #[must_use]
    pub fn concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit;
        self
    }

    /// Sets the I/O timeout for individual operations.
    #[must_use]
    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Sets the number of I/O worker threads.
    #[must_use]
    pub fn io_workers(mut self, workers: usize) -> Self {
        self.io_workers = workers;
        self
    }

    /// Sets the saturation policy for the executor.
    ///
    /// See [`SaturationPolicy`] for available options and their trade-offs.
    #[must_use]
    pub fn saturation_policy(mut self, policy: SaturationPolicy) -> Self {
        self.saturation_policy = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_network_optimized() {
        let config = MountConfig::default();
        assert_eq!(config.attr_ttl, Duration::from_secs(60));
        assert_eq!(config.negative_ttl, Duration::from_secs(30));
        assert_eq!(config.concurrency_limit, 32);
        assert_eq!(config.io_timeout, Duration::from_secs(30));
        // Dynamic based on CPU count, but always at least MIN_IO_WORKERS
        assert!(config.io_workers >= MIN_IO_WORKERS);
        assert_eq!(config.io_workers, default_io_workers());
    }

    #[test]
    fn test_default_io_workers_scales_with_cpus() {
        let workers = default_io_workers();
        let expected = num_cpus::get().saturating_mul(2).max(MIN_IO_WORKERS);
        assert_eq!(workers, expected);
        assert!(workers >= MIN_IO_WORKERS);
    }

    #[test]
    fn test_local_mode() {
        let config = MountConfig::local();
        assert_eq!(config.attr_ttl, Duration::from_secs(1));
        assert_eq!(config.negative_ttl, Duration::from_millis(500));
        assert_eq!(config.io_timeout, Duration::from_secs(10));
        // Local mode also uses dynamic worker count
        assert!(config.io_workers >= MIN_IO_WORKERS);
    }

    #[test]
    fn test_builder_pattern() {
        let config = MountConfig::default()
            .attr_ttl(Duration::from_secs(120))
            .concurrency_limit(16)
            .io_timeout(Duration::from_secs(60))
            .io_workers(4);
        assert_eq!(config.attr_ttl, Duration::from_secs(120));
        assert_eq!(config.concurrency_limit, 16);
        assert_eq!(config.io_timeout, Duration::from_secs(60));
        assert_eq!(config.io_workers, 4);
    }
}
