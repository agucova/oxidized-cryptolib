//! Benchmark definitions and execution.

mod read;
mod write;
mod metadata;
mod lifecycle;
mod runner;
mod suite;
pub mod workloads;

pub use read::{SequentialReadBenchmark, RandomReadBenchmark};
pub use write::{SequentialWriteBenchmark, RandomWriteBenchmark};
pub use metadata::{DirectoryListingBenchmark, MetadataBenchmark};
pub use lifecycle::{FileCreationBenchmark, FileDeletionBenchmark};
pub use runner::BenchmarkRunner;
pub use suite::create_suite;
pub use workloads::{create_workloads, create_workloads_filtered, create_workload_by_name, workload_names};

// Phase progress types for fine-grained workload progress reporting
// (PhaseProgress and PhaseProgressCallback are defined below and re-exported)

use crate::config::{FileSize, Implementation, OperationType};
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Progress update for workload phases.
///
/// Used by workloads with multiple internal phases (e.g., database workload)
/// to report fine-grained progress during execution.
#[derive(Debug, Clone)]
pub struct PhaseProgress {
    /// Name of the current phase (e.g., "Index lookups")
    pub phase_name: &'static str,
    /// Current phase index (0-based)
    pub phase_index: usize,
    /// Total number of phases
    pub total_phases: usize,
    /// Items completed in current phase (if applicable)
    pub items_completed: Option<usize>,
    /// Total items in current phase (if applicable)
    pub items_total: Option<usize>,
}

/// Callback for receiving phase progress updates.
///
/// Workloads call this during `run_with_progress` to report progress.
pub type PhaseProgressCallback<'a> = &'a dyn Fn(PhaseProgress);

/// Trait for filesystem benchmarks.
pub trait Benchmark: Send + Sync {
    /// Get the benchmark name.
    fn name(&self) -> &str;

    /// Get the operation type.
    fn operation(&self) -> OperationType;

    /// Get benchmark parameters for display.
    fn parameters(&self) -> HashMap<String, String>;

    /// Set up the benchmark (create test files, etc.).
    ///
    /// The `iteration` parameter allows creating unique file paths per iteration
    /// to ensure cache isolation without unmounting between iterations.
    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()>;

    /// Run a single iteration and return the duration.
    ///
    /// The `iteration` parameter allows accessing unique file paths per iteration
    /// to ensure cache isolation without unmounting between iterations.
    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration>;

    /// Clean up after the benchmark.
    ///
    /// The `iteration` parameter allows cleaning up iteration-specific files.
    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()>;

    /// Number of warmup iterations.
    fn warmup_iterations(&self) -> usize {
        3
    }

    /// Returns phase names for progress display (optional).
    ///
    /// Workloads with multiple internal phases can implement this to enable
    /// fine-grained progress reporting. The returned slice should contain
    /// the names of all phases in execution order.
    fn phases(&self) -> Option<&[&'static str]> {
        None
    }

    /// Run with phase progress callback (optional).
    ///
    /// Workloads that implement `phases()` should also implement this method
    /// to report progress during execution. The callback should be called
    /// periodically with updated `PhaseProgress` values.
    ///
    /// Default implementation ignores the callback and calls `run()`.
    fn run_with_progress(
        &self,
        mount_point: &Path,
        iteration: usize,
        _progress: Option<PhaseProgressCallback<'_>>,
    ) -> Result<Duration> {
        self.run(mount_point, iteration)
    }

    /// Returns true if this benchmark requires symlink support.
    ///
    /// Benchmarks that require symlinks will be skipped on backends that don't
    /// support them (WebDAV, NFS).
    fn requires_symlinks(&self) -> bool {
        false
    }
}

/// Result of a single benchmark.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Benchmark name.
    pub name: String,
    /// Operation type.
    pub operation: OperationType,
    /// Implementation tested.
    pub implementation: Implementation,
    /// File size (if applicable).
    pub file_size: Option<FileSize>,
    /// Individual sample durations.
    pub samples: Vec<Duration>,
    /// Total bytes processed (for throughput).
    pub bytes_processed: u64,
    /// Path to flamegraph SVG (if profiling was enabled).
    pub flamegraph_path: Option<PathBuf>,
}

impl BenchmarkResult {
    /// Create a new benchmark result.
    pub fn new(
        name: String,
        operation: OperationType,
        implementation: Implementation,
        file_size: Option<FileSize>,
    ) -> Self {
        Self {
            name,
            operation,
            implementation,
            file_size,
            samples: Vec::new(),
            bytes_processed: 0,
            flamegraph_path: None,
        }
    }

    /// Add a sample duration.
    pub fn add_sample(&mut self, duration: Duration) {
        self.samples.push(duration);
    }

    /// Add bytes processed.
    pub fn add_bytes(&mut self, bytes: u64) {
        self.bytes_processed += bytes;
    }

    /// Get the number of samples.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}
