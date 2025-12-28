//! Benchmark suite configuration.

use crate::bench::{
    Benchmark,
    DirectoryListingBenchmark,
    FileCreationBenchmark,
    FileDeletionBenchmark,
    MetadataBenchmark,
    RandomReadBenchmark,
    RandomWriteBenchmark,
    SequentialReadBenchmark,
    SequentialWriteBenchmark,
};
use crate::config::{BenchmarkConfig, BenchmarkSuite, FileSize};

/// Create benchmarks for the specified suite.
pub fn create_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    match config.suite {
        BenchmarkSuite::Quick => create_quick_suite(),
        BenchmarkSuite::Read => create_read_suite(config),
        BenchmarkSuite::Write => create_write_suite(config),
        BenchmarkSuite::Full => create_full_suite(config),
    }
}

/// Create the quick suite (minimal benchmarks for sanity check).
fn create_quick_suite() -> Vec<Box<dyn Benchmark>> {
    vec![
        Box::new(SequentialReadBenchmark::new(FileSize::Large)),
        Box::new(DirectoryListingBenchmark::new(10)),
    ]
}

/// Create the read-only suite.
fn create_read_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks: Vec<Box<dyn Benchmark>> = Vec::new();

    // Sequential reads at various sizes
    for size in config.file_sizes() {
        benchmarks.push(Box::new(SequentialReadBenchmark::new(size)));
    }

    // Random reads (only for larger files)
    for size in [FileSize::OneChunk, FileSize::Large] {
        benchmarks.push(Box::new(RandomReadBenchmark::new(size)));
    }

    // Directory listing
    for num_files in config.directory_sizes() {
        benchmarks.push(Box::new(DirectoryListingBenchmark::new(num_files)));
    }

    // Metadata operations
    benchmarks.push(Box::new(MetadataBenchmark::new(10)));

    benchmarks
}

/// Create the write-only suite.
fn create_write_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks: Vec<Box<dyn Benchmark>> = Vec::new();

    // Sequential writes at various sizes
    for size in config.file_sizes() {
        benchmarks.push(Box::new(SequentialWriteBenchmark::new(size)));
    }

    // Random writes (only for 32KB - tests chunk boundary behavior)
    benchmarks.push(Box::new(RandomWriteBenchmark::new(FileSize::OneChunk)));

    // File lifecycle
    benchmarks.push(Box::new(FileCreationBenchmark::new(100)));
    benchmarks.push(Box::new(FileDeletionBenchmark::new(100)));

    benchmarks
}

/// Create the full suite.
fn create_full_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks = create_read_suite(config);
    benchmarks.extend(create_write_suite(config));
    benchmarks
}
