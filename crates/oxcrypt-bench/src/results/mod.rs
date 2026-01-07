//! Results processing and visualization.
//!
//! This module provides hyperfine-style benchmark result output:
//! - `LiveProgressReporter` for real-time progress during execution
//! - `BenchmarkPrinter` for formatted result output

// Allow numeric casts for Duration conversions in JSON export
#![allow(clippy::cast_possible_truncation)]

pub mod bayesian;
pub mod format;
pub mod live;
pub mod phase_progress;
pub mod printer;
pub mod stats;

pub use bayesian::{bayesian_compare, BayesianComparison, BayesianConfig};
pub use format::{
    format_duration, format_mean_sigma, format_percentage, format_range, format_speedup,
    format_throughput,
};
pub use live::LiveProgressReporter;
pub use phase_progress::PhaseProgressReporter;
pub use printer::BenchmarkPrinter;
pub use stats::{compute_stats, BenchmarkStats, LatencyStats, Throughput};

use crate::bench::BenchmarkResult;
use crate::config::BenchmarkConfig;
use serde::Serialize;
use std::path::Path;

/// JSON-serializable benchmark report
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub metadata: ReportMetadata,
    pub results: Vec<BenchmarkStatsJson>,
    pub comparisons: Vec<BayesianComparison>,
}

/// Report metadata
#[derive(Debug, Clone, Serialize)]
pub struct ReportMetadata {
    pub timestamp: String,
    pub platform: String,
    pub oxbench_version: String,
    pub suite: String,
    pub iterations: usize,
    pub warmup_iterations: usize,
    pub implementations: Vec<String>,
    /// Whether flamegraph profiling was enabled
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub flamegraph_enabled: bool,
    /// Directory containing flamegraph SVGs (if profiling was enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flamegraph_dir: Option<String>,
}

/// JSON-serializable benchmark stats
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkStatsJson {
    pub name: String,
    pub operation: String,
    pub implementation: String,
    pub file_size: Option<String>,
    pub sample_count: usize,
    pub throughput_bytes_per_sec: Option<f64>,
    pub throughput_ops_per_sec: Option<f64>,
    pub latency_mean_ns: u64,
    pub latency_std_dev_ns: u64,
    pub latency_min_ns: u64,
    pub latency_max_ns: u64,
    pub latency_p50_ns: u64,
    pub latency_p95_ns: u64,
    pub latency_p99_ns: u64,
    pub raw_samples_ns: Vec<u64>,
    /// Path to flamegraph SVG (if profiling was enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flamegraph: Option<String>,
}

impl BenchmarkStatsJson {
    /// Create from stats, samples, and optional flamegraph path
    pub fn from_result(
        stats: &BenchmarkStats,
        samples: &[std::time::Duration],
        flamegraph_path: Option<&Path>,
    ) -> Self {
        Self {
            name: stats.name.clone(),
            operation: stats.operation.to_string(),
            implementation: stats.implementation.to_string(),
            file_size: stats.file_size.map(|s| s.name().to_string()),
            sample_count: stats.sample_count,
            throughput_bytes_per_sec: stats.throughput.map(|t| t.bytes_per_sec),
            throughput_ops_per_sec: stats.throughput.map(|t| t.ops_per_sec),
            latency_mean_ns: stats.latency.mean.as_nanos() as u64,
            latency_std_dev_ns: stats.latency.std_dev.as_nanos() as u64,
            latency_min_ns: stats.latency.min.as_nanos() as u64,
            latency_max_ns: stats.latency.max.as_nanos() as u64,
            latency_p50_ns: stats.latency.p50.as_nanos() as u64,
            latency_p95_ns: stats.latency.p95.as_nanos() as u64,
            latency_p99_ns: stats.latency.p99.as_nanos() as u64,
            raw_samples_ns: samples.iter().map(|d| d.as_nanos() as u64).collect(),
            flamegraph: flamegraph_path.map(|p| p.display().to_string()),
        }
    }
}

/// Generate pairwise Bayesian comparisons for all benchmarks
pub fn generate_bayesian_comparisons(
    results: &[BenchmarkResult],
    config: &BayesianConfig,
) -> Vec<BayesianComparison> {
    let mut comparisons = Vec::new();

    // Group results by benchmark name
    let mut by_benchmark: std::collections::HashMap<&str, Vec<&BenchmarkResult>> =
        std::collections::HashMap::new();
    for result in results {
        by_benchmark.entry(&result.name).or_default().push(result);
    }

    // Compare each pair of implementations for each benchmark
    for impl_results in by_benchmark.values() {
        for i in 0..impl_results.len() {
            for j in (i + 1)..impl_results.len() {
                let a = impl_results[i];
                let b = impl_results[j];

                let comparison = bayesian_compare(
                    &a.samples,
                    &b.samples,
                    &a.implementation.to_string(),
                    &b.implementation.to_string(),
                    config,
                );

                comparisons.push(comparison);
            }
        }
    }

    comparisons
}

/// Export results to JSON file
pub fn export_json(
    results: &[BenchmarkResult],
    config: &BenchmarkConfig,
    path: &Path,
) -> anyhow::Result<()> {
    let stats: Vec<BenchmarkStats> = results.iter().map(compute_stats).collect();
    let bayesian_config = BayesianConfig::default();
    let comparisons = generate_bayesian_comparisons(results, &bayesian_config);

    let stats_json: Vec<BenchmarkStatsJson> = results
        .iter()
        .zip(stats.iter())
        .map(|(result, stat)| {
            BenchmarkStatsJson::from_result(
                stat,
                result.samples.as_slice(),
                result.flamegraph_path.as_deref(),
            )
        })
        .collect();

    let report = BenchmarkReport {
        metadata: ReportMetadata {
            timestamp: chrono::Utc::now().to_rfc3339(),
            platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            oxbench_version: env!("CARGO_PKG_VERSION").to_string(),
            suite: config.suite.to_string(),
            iterations: config.effective_iterations(),
            warmup_iterations: config.warmup_iterations,
            implementations: config.implementations.iter().map(|i| i.name().to_string()).collect(),
            flamegraph_enabled: config.flamegraph_enabled,
            flamegraph_dir: if config.flamegraph_enabled {
                Some(config.flamegraph_dir.display().to_string())
            } else {
                None
            },
        },
        results: stats_json,
        comparisons,
    };

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, json)?;

    Ok(())
}
