//! Mount configuration for the FUSE filesystem.
//!
//! This module provides configuration options for tuning the filesystem
//! behavior, particularly for different storage backends (local vs network).

use oxcrypt_mount::{DEFAULT_NEGATIVE_TTL, DEFAULT_TTL, LOCAL_NEGATIVE_TTL, LOCAL_TTL};
use std::time::Duration;

/// Default I/O timeout for network backends (30 seconds).
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// I/O timeout for local backends (10 seconds).
pub const LOCAL_IO_TIMEOUT: Duration = Duration::from_secs(10);

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
}

impl Default for MountConfig {
    /// Returns the default configuration optimized for network filesystems.
    fn default() -> Self {
        Self {
            attr_ttl: DEFAULT_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            concurrency_limit: 32,
            io_timeout: DEFAULT_IO_TIMEOUT,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_network_optimized() {
        let config = MountConfig::default();
        assert_eq!(config.attr_ttl, Duration::from_secs(60));
        assert_eq!(config.negative_ttl, Duration::from_secs(3));
        assert_eq!(config.concurrency_limit, 32);
        assert_eq!(config.io_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_local_mode() {
        let config = MountConfig::local();
        assert_eq!(config.attr_ttl, Duration::from_secs(1));
        assert_eq!(config.negative_ttl, Duration::from_millis(300));
        assert_eq!(config.io_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_builder_pattern() {
        let config = MountConfig::default()
            .attr_ttl(Duration::from_secs(120))
            .concurrency_limit(16)
            .io_timeout(Duration::from_secs(60));
        assert_eq!(config.attr_ttl, Duration::from_secs(120));
        assert_eq!(config.concurrency_limit, 16);
        assert_eq!(config.io_timeout, Duration::from_secs(60));
    }
}
