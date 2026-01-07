//! Benchmark suite configuration.
//!
//! Suites are compositions of workloads. Each suite selects a subset of
//! available workloads to run together.

use crate::bench::{
    Benchmark,
    workloads::{
        WorkloadConfig, WorkloadCategory,
        create_workloads_by_names, create_workloads_filtered,
        create_io_workloads, create_metadata_workloads, create_lifecycle_workloads,
        create_synthetic_workloads, create_realistic_workloads,
        workloads_by_category,
    },
};
use crate::config::BenchmarkConfig;

/// Create benchmarks for the specified suite.
///
/// If specific workloads are selected via `--workload`, those take priority
/// over the suite setting.
pub fn create_suite(config: &BenchmarkConfig) -> Vec<Box<dyn Benchmark>> {
    let workload_config = WorkloadConfig::new(config.workload_scale)
        .with_real_assets(config.real_assets);

    // If specific workloads are requested, use those regardless of suite
    if !config.selected_workloads.is_empty() {
        return create_workloads_filtered(&workload_config, &config.selected_workloads)
            .expect("Invalid workload name");
    }

    match config.suite {
        crate::config::BenchmarkSuite::Quick => create_quick_suite(&workload_config),
        crate::config::BenchmarkSuite::Read => create_read_suite(&workload_config),
        crate::config::BenchmarkSuite::Write => create_write_suite(&workload_config),
        crate::config::BenchmarkSuite::Synthetic => create_synthetic_suite(&workload_config),
        crate::config::BenchmarkSuite::Metadata => create_metadata_suite(&workload_config),
        crate::config::BenchmarkSuite::LargeFile => create_large_file_suite(&workload_config),
        crate::config::BenchmarkSuite::Workload => {
            // No specific workloads selected, run all realistic workloads
            create_realistic_workloads(&workload_config)
        }
        crate::config::BenchmarkSuite::Complete => create_complete_suite(&workload_config),
    }
}

/// Create the quick suite (minimal benchmarks for sanity check).
fn create_quick_suite(config: &WorkloadConfig) -> Vec<Box<dyn Benchmark>> {
    // Quick suite: one read + one readdir
    create_workloads_by_names(&["seq-read", "readdir"], config)
}

/// Create the read-only suite.
fn create_read_suite(config: &WorkloadConfig) -> Vec<Box<dyn Benchmark>> {
    let mut workloads = create_workloads_by_names(
        workloads_by_category(WorkloadCategory::Read),
        config,
    );
    workloads.extend(create_metadata_workloads(config));
    workloads
}

/// Create the write-only suite.
fn create_write_suite(config: &WorkloadConfig) -> Vec<Box<dyn Benchmark>> {
    let mut workloads = create_workloads_by_names(
        workloads_by_category(WorkloadCategory::Write),
        config,
    );
    workloads.extend(create_lifecycle_workloads(config));
    workloads
}

/// Create the synthetic suite (all synthetic benchmarks).
fn create_synthetic_suite(config: &WorkloadConfig) -> Vec<Box<dyn Benchmark>> {
    create_synthetic_workloads(config)
}

/// Create the metadata-only suite.
fn create_metadata_suite(config: &WorkloadConfig) -> Vec<Box<dyn Benchmark>> {
    create_metadata_workloads(config)
}

/// Create the complete suite (synthetic + realistic workloads).
fn create_complete_suite(config: &WorkloadConfig) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks = create_synthetic_workloads(config);
    benchmarks.extend(create_realistic_workloads(config));
    benchmarks
}

/// Create the large file suite (stress tests with bigger files).
///
/// Uses a high-scale config to get larger file sizes.
fn create_large_file_suite(config: &WorkloadConfig) -> Vec<Box<dyn Benchmark>> {
    // Override scale to get larger files
    let large_config = WorkloadConfig::new(1.0) // Full scale = 10MB files
        .with_real_assets(config.real_assets);
    create_io_workloads(&large_config)
}
