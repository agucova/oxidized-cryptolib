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
    create_workloads,
};
use crate::config::{BenchmarkConfig, BenchmarkSuite, FileSize};

/// Create benchmarks for the specified suite.
pub fn create_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    match config.suite {
        BenchmarkSuite::Quick => create_quick_suite(),
        BenchmarkSuite::Read => create_read_suite(config),
        BenchmarkSuite::Write => create_write_suite(config),
        BenchmarkSuite::Full => create_full_suite(config),
        BenchmarkSuite::LargeFile => create_large_file_suite(),
        BenchmarkSuite::Workload => create_workloads(),
        BenchmarkSuite::Complete => create_complete_suite(config),
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

/// Create the full synthetic suite.
fn create_full_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks = create_read_suite(config);
    benchmarks.extend(create_write_suite(config));
    benchmarks
}

/// Create the complete suite (synthetic + workloads).
fn create_complete_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks = create_full_suite(config);
    benchmarks.extend(create_workloads());
    benchmarks
}

/// Create the large file suite (100MB - 1GB stress tests).
fn create_large_file_suite() -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks: Vec<Box<dyn Benchmark>> = Vec::new();

    // Sequential reads at large sizes
    for size in FileSize::large() {
        benchmarks.push(Box::new(SequentialReadBenchmark::new(size)));
    }

    // Sequential writes at large sizes
    for size in FileSize::large() {
        benchmarks.push(Box::new(SequentialWriteBenchmark::new(size)));
    }

    // Random reads on large files
    benchmarks.push(Box::new(RandomReadBenchmark::new(FileSize::XXLarge)));
    benchmarks.push(Box::new(RandomReadBenchmark::new(FileSize::Huge)));

    // Random writes on large files
    benchmarks.push(Box::new(RandomWriteBenchmark::new(FileSize::XXLarge)));

    benchmarks
}
