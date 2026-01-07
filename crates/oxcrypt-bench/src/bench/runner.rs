//! Benchmark execution runner.

use crate::bench::{Benchmark, BenchmarkResult, PhaseProgress};
use crate::config::{BenchmarkConfig, FileSize, Implementation};
use crate::mount::{ensure_mount_point, mount_implementation};
use crate::results::{compute_stats, BenchmarkPrinter, LiveProgressReporter, PhaseProgressReporter};
use anyhow::{Context, Result};
use oxcrypt_mount::signal;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[cfg(unix)]
use pprof::ProfilerGuardBuilder;

/// Maximum time allowed for a single benchmark run iteration.
const RUN_TIMEOUT: Duration = Duration::from_secs(60); // 1 minute per iteration

/// Maximum time for setup phase (creating test files).
const SETUP_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes (WebDAV needs more time)

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
    cache_strategy: CacheClearStrategy,
}

impl BenchmarkRunner {
    /// Create a new benchmark runner.
    ///
    /// Will attempt to acquire sudo privileges for cache clearing if multiple
    /// implementations are being benchmarked. Falls back to wait-only strategy
    /// if sudo is unavailable.
    ///
    /// Note: Signal handling is done by oxcrypt_mount::signal module which should
    /// be installed in main() before creating the runner.
    pub fn new(config: BenchmarkConfig) -> Self {
        // Determine cache clearing strategy
        let cache_strategy = if config.implementations.len() > 1 {
            Self::acquire_sudo_if_needed()
        } else {
            // Single implementation doesn't need cache clearing between runs
            CacheClearStrategy::WaitOnly
        };

        Self {
            config,
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

    /// Check if shutdown was requested via signal.
    pub fn should_stop(&self) -> bool {
        signal::shutdown_requested()
    }

    /// Run all benchmarks and return results.
    ///
    /// Uses sequential mounting: mount one implementation, run all benchmarks,
    /// unmount, then move to the next. This prevents concurrent vault access
    /// and reduces cache interference between implementations.
    ///
    /// Output is printed during execution in hyperfine-style format:
    /// - Live progress bar with spinner and ETA during each benchmark
    /// - Immediate result output after each benchmark completes
    /// - Summary comparison at the end
    pub fn run(&self, benchmarks: &[Box<dyn Benchmark>]) -> Result<Vec<BenchmarkResult>> {
        let mut results = Vec::new();
        let mut all_stats = Vec::new();

        // Ensure flamegraph output directory exists
        self.ensure_flamegraph_dir()?;

        // Create printer for hyperfine-style output
        let printer = BenchmarkPrinter::new(self.config.color);

        tracing::info!(
            "Running {} benchmarks across {} implementations",
            benchmarks.len(),
            self.config.implementations.len()
        );

        if self.config.flamegraph_enabled {
            tracing::info!(
                "Flamegraph profiling enabled ({}Hz), output: {}",
                self.config.profile_frequency,
                self.config.flamegraph_dir.display()
            );
        }

        // Run benchmarks for each implementation sequentially
        for (impl_idx, &impl_type) in self.config.implementations.iter().enumerate() {
            if self.should_stop() {
                anyhow::bail!("Interrupted");
            }

            // Add pause between implementations to help clear OS caches
            if impl_idx > 0 {
                tracing::debug!("Clearing caches before {}...", impl_type);
                self.clear_caches();
            }

            // Mount this implementation
            let mount_point = self.config.mount_point(impl_type);

            // Print mount status - use eprintln to avoid garbled output with tracing warnings
            match impl_type {
                Implementation::OfficialCryptomator => {
                    eprintln!("Validating {} mount...", impl_type.short_name());
                }
                Implementation::OxidizedFileProvider => {
                    eprintln!("Mounting {} (this may take a few seconds)...", impl_type.short_name());
                }
                _ => {
                    eprintln!("Mounting {} (this may take a few seconds)...", impl_type.short_name());
                }
            }

            // Only ensure mount point for internal mounts - external mounts (Cryptomator)
            // are already mounted by the user and we shouldn't try to clean them up
            // ensure_mount_point may return an alternative path if ghost mounts block the original
            let actual_mount_point = if impl_type != Implementation::OfficialCryptomator {
                ensure_mount_point(&mount_point)?
            } else {
                mount_point.clone()
            };

            let mount = mount_implementation(
                impl_type,
                &self.config.vault_path,
                &self.config.password,
                &actual_mount_point,
            )
            .with_context(|| format!("Failed to mount {impl_type}"))?;

            eprintln!("  Mount ready.");

            // Run all benchmarks for this implementation
            let mut mount = Some(mount);

            for benchmark in benchmarks {
                if self.should_stop() {
                    drop(mount.take()); // Ensure unmount on interrupt
                    anyhow::bail!("Interrupted");
                }

                // Skip benchmarks that require symlinks on backends that don't support them
                if benchmark.requires_symlinks() && impl_type.is_network_backend() {
                    tracing::info!(
                        "Skipping {} on {} (requires symlink support)",
                        benchmark.name(),
                        impl_type.short_name()
                    );
                    eprintln!(
                        "  Skipping {} (requires symlink support, not available on {})",
                        benchmark.name(),
                        impl_type.short_name()
                    );
                    continue;
                }

                // Log inode count for workloads to help diagnose memory issues
                // Note: Remounting between workloads is disabled to allow reproducing
                // potential inode table growth issues.
                if benchmark.operation().is_workload()
                    && let Some(ref m) = mount
                        && let Some(stats) = m.stats() {
                            let inode_count = stats.get_inode_count();
                            tracing::info!(
                                "{} inode table size: {} entries",
                                impl_type,
                                inode_count
                            );
                        }

                // Get mount point before taking mutable reference to mount
                let mount_point_path = mount.as_ref()
                    .expect("Mount should be present")
                    .mount_point()
                    .to_path_buf();

                // Check if benchmark has phases for fine-grained progress
                let result = if let Some(phases) = benchmark.phases() {
                    // Use phase-aware progress reporter
                    let phase_reporter = PhaseProgressReporter::new(
                        benchmark.name(),
                        impl_type.short_name(),
                        phases.len(),
                        self.config.color,
                    );

                    let result = self.run_single_benchmark_with_phase_progress(
                        benchmark.as_ref(),
                        &mount_point_path,
                        impl_type,
                        &phase_reporter,
                        &mut mount,
                    )?;

                    phase_reporter.finish();
                    result
                } else {
                    // Use iteration-level progress reporter for benchmarks without phases
                    let iterations = self.config.effective_iterations();
                    let mut reporter = LiveProgressReporter::new(
                        benchmark.name(),
                        impl_type.short_name(),
                        iterations,
                        self.config.color,
                    );

                    let result = self.run_single_benchmark_with_progress(
                        benchmark.as_ref(),
                        &mount_point_path,
                        impl_type,
                        &mut reporter,
                        &mut mount,
                    )?;

                    reporter.finish();
                    result
                };
                let stats = compute_stats(&result);
                printer.print_result(&stats);

                all_stats.push(stats);
                results.push(result);
            }

            // Print lock metrics if available (currently only FUSE backend supports this)
            if let Some(ref m) = mount
                && let Some(metrics) = m.lock_metrics() {
                    let snapshot = metrics.snapshot();
                    snapshot.print();
                }

            // Unmount before moving to next implementation
            tracing::debug!("Unmounting {}...", impl_type);
            drop(mount.take());

            // Brief pause to ensure clean unmount
            std::thread::sleep(Duration::from_millis(500));
        }

        // Print summary comparison (only if multiple implementations)
        printer.print_summary(&all_stats);

        Ok(results)
    }

    /// Generate path for a per-benchmark flamegraph.
    fn flamegraph_path(&self, benchmark_name: &str, impl_type: Implementation) -> PathBuf {
        let sanitized_name = benchmark_name
            .replace(['/', ' ', ':', '(', ')'], "_")
            .replace("__", "_");
        self.config
            .flamegraph_dir
            .join(format!("{}_{}.svg", impl_type.short_name().to_lowercase(), sanitized_name))
    }

    /// Ensure the flamegraph output directory exists.
    fn ensure_flamegraph_dir(&self) -> Result<()> {
        if self.config.flamegraph_enabled && !self.config.flamegraph_dir.exists() {
            std::fs::create_dir_all(&self.config.flamegraph_dir).with_context(|| {
                format!(
                    "Failed to create flamegraph directory: {}",
                    self.config.flamegraph_dir.display()
                )
            })?;
        }
        Ok(())
    }

    /// Generate a flamegraph SVG from a pprof report.
    #[cfg(unix)]
    fn write_flamegraph(
        guard: &pprof::ProfilerGuard<'_>,
        path: &std::path::Path,
    ) -> Result<()> {
        let report = guard
            .report()
            .build()
            .context("Failed to build profiler report")?;

        // Check if we have any samples
        // report.data is HashMap<Frames, isize> where isize is the sample count per stack trace
        let unique_stacks = report.data.len();
        let total_samples: isize = report.data.values().copied().sum();

        if total_samples == 0 {
            tracing::warn!(
                "No profiler samples collected for {} - benchmark may be too fast for sampling",
                path.display()
            );
        } else {
            tracing::info!(
                "Collected {} samples across {} unique stack traces for {}",
                total_samples,
                unique_stacks,
                path.display()
            );
        }

        let file = std::fs::File::create(path)
            .with_context(|| format!("Failed to create flamegraph file: {}", path.display()))?;

        report
            .flamegraph(file)
            .context("Failed to write flamegraph SVG")?;

        tracing::debug!("Wrote flamegraph to {}", path.display());
        Ok(())
    }

    /// Clear OS caches between implementations.
    ///
    /// Uses sudo if available, otherwise falls back to extended waits.
    fn clear_caches(&self) {
        match self.cache_strategy {
            CacheClearStrategy::Sudo => Self::clear_caches_with_sudo(),
            CacheClearStrategy::WaitOnly => Self::clear_caches_wait_only(),
        }
    }

    /// Clear caches using sudo (effective method).
    fn clear_caches_with_sudo() {
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
    fn clear_caches_wait_only() {
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

    /// Run a single benchmark for a single implementation with live progress reporting.
    fn run_single_benchmark_with_progress(
        &self,
        benchmark: &dyn Benchmark,
        mount_point: &std::path::Path,
        implementation: Implementation,
        reporter: &mut LiveProgressReporter,
        _mount_handle: &mut Option<crate::mount::BenchMount>,
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

        // Run warmup iterations (results are discarded)
        // Warmup helps stabilize JIT, connection pools, and cache behavior
        let warmup_iterations = benchmark.warmup_iterations();
        if warmup_iterations > 0 {
            tracing::debug!(
                "Running {} warmup iterations for {}",
                warmup_iterations,
                benchmark.name()
            );

            // Setup for warmup iteration
            // Use usize::MAX as sentinel value to avoid collision with actual iterations
            const WARMUP_ITER: usize = usize::MAX;
            let setup_start = Instant::now();
            if let Err(e) = benchmark.setup(mount_point, WARMUP_ITER) {
                if self.should_stop() {
                    anyhow::bail!("Interrupted");
                }
                return Err(e).with_context(|| format!("Warmup setup failed for {}", benchmark.name()));
            }
            let setup_elapsed = setup_start.elapsed();
            if setup_elapsed > SETUP_TIMEOUT {
                anyhow::bail!(
                    "Warmup setup for {} took {:?}, exceeding timeout of {:?}",
                    benchmark.name(),
                    setup_elapsed,
                    SETUP_TIMEOUT
                );
            }
            tracing::debug!("Warmup setup completed in {:?}", setup_elapsed);
            std::thread::sleep(Duration::from_millis(100));

            for i in 0..warmup_iterations {
                if self.should_stop() {
                    break;
                }
                match benchmark.run(mount_point, WARMUP_ITER) {
                    Ok(duration) => {
                        tracing::trace!(
                            "Warmup {}/{} for {}: {:?}",
                            i + 1,
                            warmup_iterations,
                            benchmark.name(),
                            duration
                        );
                    }
                    Err(e) => {
                        tracing::debug!("Warmup {} failed (non-fatal): {}", i + 1, e);
                    }
                }
            }

            // Cleanup after warmup
            if let Err(e) = benchmark.cleanup(mount_point, WARMUP_ITER) {
                tracing::debug!("Warmup cleanup failed: {}", e);
            }

            // Brief pause after warmup to let system settle
            std::thread::sleep(Duration::from_millis(100));
        }

        // Start per-benchmark profiler (after warmup, so we only measure actual runs)
        #[cfg(unix)]
        let profiler_guard = if self.config.flamegraph_enabled {
            match ProfilerGuardBuilder::default()
                .frequency(self.config.profile_frequency)
                .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                .build()
            {
                Ok(guard) => {
                    tracing::debug!("Started profiler for {}", benchmark.name());
                    Some(guard)
                }
                Err(e) => {
                    tracing::warn!("Failed to start profiler for {}: {}", benchmark.name(), e);
                    None
                }
            }
        } else {
            None
        };

        // Actual measurements with timeout enforcement
        let iterations = self.config.effective_iterations();
        let mut timeout_count = 0;
        for i in 0..iterations {
            if self.should_stop() {
                break;
            }

            // Setup for this iteration
            let setup_start = Instant::now();
            if let Err(e) = benchmark.setup(mount_point, i) {
                if self.should_stop() {
                    break;
                }
                tracing::warn!("Setup failed for iteration {}: {}", i, e);
                continue;
            }
            let setup_elapsed = setup_start.elapsed();
            if setup_elapsed > SETUP_TIMEOUT {
                tracing::warn!(
                    "Setup for iteration {} took {:?}, exceeding timeout of {:?}",
                    i,
                    setup_elapsed,
                    SETUP_TIMEOUT
                );
                continue;
            }
            std::thread::sleep(Duration::from_millis(100));

            let iter_start = Instant::now();
            match benchmark.run(mount_point, i) {
                Ok(duration) => {
                    let wall_time = iter_start.elapsed();

                    // Check if this iteration took too long
                    if wall_time > RUN_TIMEOUT {
                        timeout_count += 1;
                        tracing::warn!(
                            "Iteration {} of {} took {:?} (exceeds {:?} timeout)",
                            i + 1,
                            benchmark.name(),
                            wall_time,
                            RUN_TIMEOUT
                        );
                        // If too many timeouts, abort this benchmark
                        if timeout_count >= 3 {
                            tracing::error!(
                                "Aborting {} after {} timeout violations",
                                benchmark.name(),
                                timeout_count
                            );
                            break;
                        }
                    }

                    result.add_sample(duration);

                    // Track bytes for throughput calculation
                    if let Some(size) = file_size {
                        result.add_bytes(size.bytes() as u64);
                    }

                    // Update live progress with this sample
                    reporter.tick(duration);
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

            // Cleanup after this iteration
            if let Err(e) = benchmark.cleanup(mount_point, i) {
                tracing::debug!("Cleanup failed for iteration {}: {}", i, e);
            }

            // Pause between iterations
            if i < iterations - 1 {
                let pause = if benchmark.operation().is_workload() {
                    Duration::from_secs(1)
                } else {
                    Duration::from_millis(500)
                };
                std::thread::sleep(pause);
            }
        }

        // Stop profiler and generate per-benchmark flamegraph
        #[cfg(unix)]
        if let Some(guard) = profiler_guard {
            let flamegraph_path = self.flamegraph_path(benchmark.name(), implementation);
            match Self::write_flamegraph(&guard, &flamegraph_path) {
                Ok(()) => {
                    tracing::debug!("Wrote flamegraph: {}", flamegraph_path.display());
                    result.flamegraph_path = Some(flamegraph_path);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to write flamegraph for {}: {}",
                        benchmark.name(),
                        e
                    );
                }
            }
        }

        Ok(result)
    }

    /// Run a single benchmark with phase-aware progress reporting.
    ///
    /// Used for workloads that implement `phases()` to provide fine-grained
    /// progress during execution.
    fn run_single_benchmark_with_phase_progress(
        &self,
        benchmark: &dyn Benchmark,
        mount_point: &std::path::Path,
        implementation: Implementation,
        reporter: &PhaseProgressReporter,
        _mount_handle: &mut Option<crate::mount::BenchMount>,
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

        // Use usize::MAX as sentinel value for warmup to avoid collision with actual iterations
        const WARMUP_ITER: usize = usize::MAX;

        // Clean up any leftover warmup files from previous runs
        if let Err(e) = benchmark.cleanup(mount_point, WARMUP_ITER) {
            tracing::debug!("Pre-setup cleanup (expected if first run): {}", e);
        }

        // Brief pause to let filesystem settle after cleanup
        std::thread::sleep(Duration::from_millis(100));

        // Setup with timeout check
        let setup_start = Instant::now();
        if let Err(e) = benchmark.setup(mount_point, WARMUP_ITER) {
            // Check if this error occurred during shutdown
            if self.should_stop() {
                anyhow::bail!("Interrupted");
            }
            return Err(e).with_context(|| format!("Setup failed for {}", benchmark.name()));
        }

        let setup_elapsed = setup_start.elapsed();
        if setup_elapsed > SETUP_TIMEOUT {
            anyhow::bail!(
                "Setup for {} took {:?}, exceeding timeout of {:?}",
                benchmark.name(),
                setup_elapsed,
                SETUP_TIMEOUT
            );
        }
        tracing::debug!("Setup completed in {:?}", setup_elapsed);

        // Brief pause to let filesystem sync after setup
        std::thread::sleep(Duration::from_millis(100));

        // Run warmup iterations using run_with_progress (without callback)
        let warmup_iterations = benchmark.warmup_iterations();
        if warmup_iterations > 0 {
            tracing::debug!(
                "Running {} warmup iterations for {}",
                warmup_iterations,
                benchmark.name()
            );
            for i in 0..warmup_iterations {
                if self.should_stop() {
                    break;
                }
                match benchmark.run_with_progress(mount_point, WARMUP_ITER, None) {
                    Ok(duration) => {
                        tracing::trace!(
                            "Warmup {}/{} for {}: {:?}",
                            i + 1,
                            warmup_iterations,
                            benchmark.name(),
                            duration
                        );
                    }
                    Err(e) => {
                        tracing::debug!("Warmup {} failed (non-fatal): {}", i + 1, e);
                    }
                }
            }

            // Cleanup after warmup
            if let Err(e) = benchmark.cleanup(mount_point, WARMUP_ITER) {
                tracing::debug!("Warmup cleanup failed: {}", e);
            }

            // Brief pause after warmup to let system settle
            std::thread::sleep(Duration::from_millis(100));
        }

        // Start per-benchmark profiler (after warmup, so we only measure actual runs)
        #[cfg(unix)]
        let profiler_guard = if self.config.flamegraph_enabled {
            match ProfilerGuardBuilder::default()
                .frequency(self.config.profile_frequency)
                .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                .build()
            {
                Ok(guard) => {
                    tracing::debug!("Started profiler for {}", benchmark.name());
                    Some(guard)
                }
                Err(e) => {
                    tracing::warn!("Failed to start profiler for {}: {}", benchmark.name(), e);
                    None
                }
            }
        } else {
            None
        };

        // Create progress callback that updates the reporter
        let progress_callback = |progress: PhaseProgress| {
            reporter.update(&progress);
        };

        // Actual measurements with phase progress reporting
        let iterations = self.config.effective_iterations();
        let mut timeout_count = 0;
        for i in 0..iterations {
            if self.should_stop() {
                break;
            }

            // Setup for this iteration
            let setup_start = Instant::now();
            if let Err(e) = benchmark.setup(mount_point, i) {
                if self.should_stop() {
                    break;
                }
                tracing::warn!("Setup failed for iteration {}: {}", i, e);
                continue;
            }
            let setup_elapsed = setup_start.elapsed();
            if setup_elapsed > SETUP_TIMEOUT {
                tracing::warn!(
                    "Setup for iteration {} took {:?}, exceeding timeout of {:?}",
                    i,
                    setup_elapsed,
                    SETUP_TIMEOUT
                );
                continue;
            }
            std::thread::sleep(Duration::from_millis(100));

            let iter_start = Instant::now();
            match benchmark.run_with_progress(mount_point, i, Some(&progress_callback)) {
                Ok(duration) => {
                    let wall_time = iter_start.elapsed();

                    // Check if this iteration took too long
                    if wall_time > RUN_TIMEOUT {
                        timeout_count += 1;
                        tracing::warn!(
                            "Iteration {} of {} took {:?} (exceeds {:?} timeout)",
                            i + 1,
                            benchmark.name(),
                            wall_time,
                            RUN_TIMEOUT
                        );
                        // If too many timeouts, abort this benchmark
                        if timeout_count >= 3 {
                            tracing::error!(
                                "Aborting {} after {} timeout violations",
                                benchmark.name(),
                                timeout_count
                            );
                            break;
                        }
                    }

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

            // Cleanup after this iteration
            if let Err(e) = benchmark.cleanup(mount_point, i) {
                tracing::debug!("Cleanup failed for iteration {}: {}", i, e);
            }

            // Pause between iterations
            if i < iterations - 1 {
                let pause = if benchmark.operation().is_workload() {
                    Duration::from_secs(1)
                } else {
                    Duration::from_millis(500)
                };
                std::thread::sleep(pause);
            }
        }

        // Stop profiler and generate per-benchmark flamegraph
        #[cfg(unix)]
        if let Some(guard) = profiler_guard {
            let flamegraph_path = self.flamegraph_path(benchmark.name(), implementation);
            match Self::write_flamegraph(&guard, &flamegraph_path) {
                Ok(()) => {
                    tracing::debug!("Wrote flamegraph: {}", flamegraph_path.display());
                    result.flamegraph_path = Some(flamegraph_path);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to write flamegraph for {}: {}",
                        benchmark.name(),
                        e
                    );
                }
            }
        }

        Ok(result)
    }
}
