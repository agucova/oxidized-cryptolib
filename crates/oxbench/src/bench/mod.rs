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
pub use workloads::create_workloads;

use crate::config::{FileSize, Implementation, OperationType};
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Trait for filesystem benchmarks.
pub trait Benchmark: Send + Sync {
    /// Get the benchmark name.
    fn name(&self) -> &str;

    /// Get the operation type.
    fn operation(&self) -> OperationType;

    /// Get benchmark parameters for display.
    fn parameters(&self) -> HashMap<String, String>;

    /// Set up the benchmark (create test files, etc.).
    fn setup(&self, mount_point: &Path) -> Result<()>;

    /// Run a single iteration and return the duration.
    fn run(&self, mount_point: &Path) -> Result<Duration>;

    /// Clean up after the benchmark.
    fn cleanup(&self, mount_point: &Path) -> Result<()>;

    /// Number of warmup iterations.
    fn warmup_iterations(&self) -> usize {
        3
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
