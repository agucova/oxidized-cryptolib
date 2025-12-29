//! Benchmark execution runner.

use crate::bench::{Benchmark, BenchmarkResult};
use crate::config::{BenchmarkConfig, FileSize, Implementation};
use crate::mount::{ensure_mount_point, mount_implementation};
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Cache clearing strategy based on available privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheClearStrategy {
    /// Use sudo for effective cache clearing (purge on macOS, drop_caches on Linux)
    Sudo,
    /// Fall back to longer waits without sudo
    WaitOnly,
}

/// Benchmark runner that executes benchmarks across implementations.
///
/// Uses sequential mounting to avoid:
/// - Concurrent access conflicts on the same vault
/// - OS page cache cross-contamination between implementations
/// - Write conflicts that could corrupt vault data
pub struct BenchmarkRunner {
    config: BenchmarkConfig,
    shutdown: Arc<AtomicBool>,
    cache_strategy: CacheClearStrategy,
}

impl BenchmarkRunner {
    /// Create a new benchmark runner.
    ///
    /// Will attempt to acquire sudo privileges for cache clearing if multiple
    /// implementations are being benchmarked. Falls back to wait-only strategy
    /// if sudo is unavailable.
    pub fn new(config: BenchmarkConfig) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));

        // Set up signal handler
        let shutdown_clone = shutdown.clone();
        ctrlc::set_handler(move || {
            eprintln!("\nInterrupted, cleaning up...");
            shutdown_clone.store(true, Ordering::SeqCst);
        })
        .ok();

        // Determine cache clearing strategy
        let cache_strategy = if config.implementations.len() > 1 {
            Self::acquire_sudo_if_needed()
        } else {
            // Single implementation doesn't need cache clearing between runs
            CacheClearStrategy::WaitOnly
        };

        Self {
            config,
            shutdown,
            cache_strategy,
        }
    }

    /// Attempt to acquire sudo privileges for cache clearing.
    ///
    /// Uses `sudo -v` to validate/refresh credentials. If the user has already
    /// authenticated recently, this won't prompt. Otherwise, it will prompt
    /// for password.
    fn acquire_sudo_if_needed() -> CacheClearStrategy {
        eprintln!("Checking sudo access for cache clearing between implementations...");

        // Try to validate sudo credentials
        // -v updates the cached credentials without running a command
        // -n runs non-interactively (fails if password needed but not cached)
        let non_interactive = std::process::Command::new("sudo")
            .args(["-n", "-v"])
            .stderr(std::process::Stdio::null())
            .status();

        match non_interactive {
            Ok(status) if status.success() => {
                eprintln!("  Using existing sudo credentials for cache clearing.");
                return CacheClearStrategy::Sudo;
            }
            _ => {
                // Need to prompt for password
                eprintln!("  Sudo access recommended for accurate benchmarks (clears OS caches).");
                eprintln!("  Enter password to enable, or press Ctrl+C and re-run without sudo.\n");
            }
        }

        // Try interactive sudo -v
        let interactive = std::process::Command::new("sudo")
            .arg("-v")
            .status();

        match interactive {
            Ok(status) if status.success() => {
                eprintln!("  Sudo access granted. Will clear caches between implementations.\n");
                CacheClearStrategy::Sudo
            }
            _ => {
                eprintln!("  Sudo not available. Using extended waits between implementations.");
                eprintln!("  Note: Results may be less accurate due to OS cache effects.\n");
                CacheClearStrategy::WaitOnly
            }
        }
    }

    /// Check if shutdown was requested.
    pub fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Run all benchmarks and return results.
    ///
    /// Uses sequential mounting: mount one implementation, run all benchmarks,
    /// unmount, then move to the next. This prevents concurrent vault access
    /// and reduces cache interference between implementations.
    pub fn run(&self, benchmarks: &[Box<dyn Benchmark>]) -> Result<Vec<BenchmarkResult>> {
        let mut results = Vec::new();

        // Calculate total operations for progress bar
        let total_ops = benchmarks.len() * self.config.implementations.len();
        let progress = ProgressBar::new(total_ops as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        tracing::info!(
            "Running {} benchmarks across {} implementations (sequential mounting)",
            benchmarks.len(),
            self.config.implementations.len()
        );

        // Run benchmarks for each implementation sequentially
        for (impl_idx, &impl_type) in self.config.implementations.iter().enumerate() {
            if self.should_stop() {
                progress.finish_with_message("Interrupted");
                anyhow::bail!("Interrupted");
            }

            // Add pause between implementations to help clear OS caches
            if impl_idx > 0 {
                progress.set_message(format!("Clearing caches before {}...", impl_type));
                self.clear_caches();
            }

            // Mount this implementation
            let mount_point = self.config.mount_point(impl_type);
            ensure_mount_point(&mount_point)?;

            progress.set_message(format!("Mounting {}...", impl_type));

            match impl_type {
                Implementation::OfficialCryptomator => {
                    tracing::info!("Validating Cryptomator mount at {}", mount_point.display());
                }
                _ => {
                    tracing::info!("Mounting {} at {}", impl_type, mount_point.display());
                }
            }

            let mount = mount_implementation(
                impl_type,
                &self.config.vault_path,
                &self.config.password,
                &mount_point,
            )
            .with_context(|| format!("Failed to mount {}", impl_type))?;

            // Run all benchmarks for this implementation
            for benchmark in benchmarks {
                if self.should_stop() {
                    drop(mount); // Ensure unmount on interrupt
                    progress.finish_with_message("Interrupted");
                    anyhow::bail!("Interrupted");
                }

                progress.set_message(format!("{} - {}", impl_type, benchmark.name()));

                let result = self.run_single_benchmark(
                    benchmark.as_ref(),
                    mount.mount_point(),
                    impl_type,
                )?;

                results.push(result);
                progress.inc(1);
            }

            // Unmount before moving to next implementation
            tracing::info!("Unmounting {}...", impl_type);
            drop(mount);

            // Brief pause to ensure clean unmount
            std::thread::sleep(Duration::from_millis(500));
        }

        progress.finish_with_message("Complete");

        Ok(results)
    }

    /// Clear OS caches between implementations.
    ///
    /// Uses sudo if available, otherwise falls back to extended waits.
    fn clear_caches(&self) {
        match self.cache_strategy {
            CacheClearStrategy::Sudo => self.clear_caches_with_sudo(),
            CacheClearStrategy::WaitOnly => self.clear_caches_wait_only(),
        }
    }

    /// Clear caches using sudo (effective method).
    fn clear_caches_with_sudo(&self) {
        // Brief pause to allow async I/O to settle
        std::thread::sleep(Duration::from_secs(1));

        #[cfg(target_os = "macos")]
        {
            match std::process::Command::new("sudo")
                .args(["-n", "purge"]) // -n for non-interactive (we already have credentials)
                .status()
            {
                Ok(status) if status.success() => {
                    tracing::debug!("Successfully cleared macOS disk cache");
                }
                _ => {
                    // Fall back to wait if sudo expired
                    tracing::debug!("Sudo expired, using extended wait");
                    std::thread::sleep(Duration::from_secs(4));
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Sync first to flush writes
            let _ = std::process::Command::new("sync").status();

            match std::process::Command::new("sudo")
                .args(["-n", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
                .status()
            {
                Ok(status) if status.success() => {
                    tracing::debug!("Successfully cleared Linux page cache");
                }
                _ => {
                    // Fall back to wait if sudo expired
                    tracing::debug!("Sudo expired, using extended wait");
                    std::thread::sleep(Duration::from_secs(4));
                }
            }
        }

        // Brief pause after cache clear
        std::thread::sleep(Duration::from_secs(1));
    }

    /// Clear caches using only waits (less effective, but doesn't require sudo).
    fn clear_caches_wait_only(&self) {
        // Without sudo, we use extended waits to let the OS naturally evict
        // some cached pages. This is less reliable but better than nothing.
        tracing::debug!("Using extended wait for cache clearing (no sudo)");

        // Sync to flush writes
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("sync").status();
        }

        // Extended wait to allow natural cache pressure
        // 5 seconds gives the OS time to potentially evict some pages
        std::thread::sleep(Duration::from_secs(5));
    }

    /// Run a single benchmark for a single implementation.
    fn run_single_benchmark(
        &self,
        benchmark: &dyn Benchmark,
        mount_point: &std::path::Path,
        implementation: Implementation,
    ) -> Result<BenchmarkResult> {
        // Determine file size from parameters
        let file_size = benchmark
            .parameters()
            .get("file_size")
            .and_then(|s| match s.as_str() {
                "1KB" => Some(FileSize::Tiny),
                "32KB" => Some(FileSize::OneChunk),
                "100KB" => Some(FileSize::Medium),
                "1MB" => Some(FileSize::Large),
                "10MB" => Some(FileSize::XLarge),
                _ => None,
            });

        let mut result = BenchmarkResult::new(
            benchmark.name().to_string(),
            benchmark.operation(),
            implementation,
            file_size,
        );

        // Clean up any leftover files from previous runs before setup
        if let Err(e) = benchmark.cleanup(mount_point) {
            tracing::debug!("Pre-setup cleanup (expected if first run): {}", e);
        }

        // Brief pause to let filesystem settle after cleanup
        std::thread::sleep(Duration::from_millis(100));

        // Setup
        benchmark
            .setup(mount_point)
            .with_context(|| format!("Setup failed for {}", benchmark.name()))?;

        // Brief pause to let filesystem sync after setup
        std::thread::sleep(Duration::from_millis(100));

        // Warmup iterations
        for _ in 0..self.config.warmup_iterations {
            if self.should_stop() {
                break;
            }
            let _ = benchmark.run(mount_point);
        }

        // Actual measurements
        let iterations = self.config.effective_iterations();
        for i in 0..iterations {
            if self.should_stop() {
                break;
            }

            match benchmark.run(mount_point) {
                Ok(duration) => {
                    result.add_sample(duration);

                    // Track bytes for throughput calculation
                    if let Some(size) = file_size {
                        result.add_bytes(size.bytes() as u64);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Iteration {} of {} failed: {}",
                        i + 1,
                        benchmark.name(),
                        e
                    );
                }
            }
        }

        // Cleanup
        if let Err(e) = benchmark.cleanup(mount_point) {
            tracing::warn!("Cleanup failed for {}: {}", benchmark.name(), e);
        }

        Ok(result)
    }
}
