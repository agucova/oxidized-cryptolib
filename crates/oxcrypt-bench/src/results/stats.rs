//! Statistics computation for benchmark results.

// Allow numeric casts in this module - all statistical calculations involve conversions
// between Duration (u64 nanos), f64 (for floating point math), and usize (for indexing).
// These are all intentional and necessary for accurate statistics.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]

use crate::bench::BenchmarkResult;
use crate::config::{FileSize, Implementation, OperationType};
use std::time::Duration;

/// Computed statistics for a benchmark.
#[derive(Debug, Clone)]
pub struct BenchmarkStats {
    /// Benchmark name.
    pub name: String,
    /// Operation type.
    pub operation: OperationType,
    /// Implementation tested.
    pub implementation: Implementation,
    /// File size (if applicable).
    pub file_size: Option<FileSize>,
    /// Number of samples.
    pub sample_count: usize,
    /// Throughput metrics.
    pub throughput: Option<Throughput>,
    /// Latency statistics.
    pub latency: LatencyStats,
}

/// Throughput metrics.
#[derive(Debug, Clone, Copy)]
pub struct Throughput {
    /// Bytes per second.
    pub bytes_per_sec: f64,
    /// Operations per second.
    pub ops_per_sec: f64,
}

/// Latency statistics.
#[derive(Debug, Clone, Copy)]
pub struct LatencyStats {
    /// Mean latency.
    pub mean: Duration,
    /// Standard deviation.
    pub std_dev: Duration,
    /// Minimum latency.
    pub min: Duration,
    /// Maximum latency.
    pub max: Duration,
    /// 50th percentile (median).
    pub p50: Duration,
    /// 95th percentile.
    pub p95: Duration,
    /// 99th percentile.
    pub p99: Duration,
}

/// Compute statistics for a benchmark result.
pub fn compute_stats(result: &BenchmarkResult) -> BenchmarkStats {
    let samples = &result.samples;

    if samples.is_empty() {
        return BenchmarkStats {
            name: result.name.clone(),
            operation: result.operation,
            implementation: result.implementation,
            file_size: result.file_size,
            sample_count: 0,
            throughput: None,
            latency: LatencyStats {
                mean: Duration::ZERO,
                std_dev: Duration::ZERO,
                min: Duration::ZERO,
                max: Duration::ZERO,
                p50: Duration::ZERO,
                p95: Duration::ZERO,
                p99: Duration::ZERO,
            },
        };
    }

    // Convert to nanoseconds for calculation
    let nanos: Vec<u64> = samples.iter().map(|d| d.as_nanos() as u64).collect();

    // Calculate mean
    let sum: u64 = nanos.iter().sum();
    let mean_ns = sum as f64 / nanos.len() as f64;

    // Calculate standard deviation
    let variance: f64 = nanos
        .iter()
        .map(|&n| {
            let diff = n as f64 - mean_ns;
            diff * diff
        })
        .sum::<f64>()
        / nanos.len() as f64;
    let std_dev_ns = variance.sqrt();

    // Sort for percentiles
    let mut sorted = nanos.clone();
    sorted.sort_unstable();

    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let p50 = percentile(&sorted, 50);
    let p95 = percentile(&sorted, 95);
    let p99 = percentile(&sorted, 99);

    // Calculate throughput (only for I/O benchmarks that track bytes)
    let throughput = if result.bytes_processed > 0 {
        let total_time_secs = sum as f64 / 1_000_000_000.0;
        Some(Throughput {
            bytes_per_sec: result.bytes_processed as f64 / total_time_secs,
            ops_per_sec: samples.len() as f64 / total_time_secs,
        })
    } else {
        // For operation-focused benchmarks (file creation, deletion, metadata, etc.)
        // don't report throughput since they don't process bytes
        None
    };

    BenchmarkStats {
        name: result.name.clone(),
        operation: result.operation,
        implementation: result.implementation,
        file_size: result.file_size,
        sample_count: samples.len(),
        throughput,
        latency: LatencyStats {
            mean: Duration::from_nanos(mean_ns as u64),
            std_dev: Duration::from_nanos(std_dev_ns as u64),
            min: Duration::from_nanos(min),
            max: Duration::from_nanos(max),
            p50: Duration::from_nanos(p50),
            p95: Duration::from_nanos(p95),
            p99: Duration::from_nanos(p99),
        },
    }
}

/// Calculate percentile from sorted data using linear interpolation.
///
/// Uses NumPy's "linear" interpolation method for accurate percentiles
/// even with small sample sizes. This ensures P95 and P99 give different
/// values when there's sufficient data spread.
fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }

    // NumPy-style linear interpolation
    // idx = p/100 * (n - 1), then interpolate between floor(idx) and ceil(idx)
    let n = sorted.len() as f64;
    let idx = (p as f64 / 100.0) * (n - 1.0);

    let lo = idx.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = idx - lo as f64;

    // Linear interpolation between adjacent values
    let result = sorted[lo] as f64 * (1.0 - frac) + sorted[hi] as f64 * frac;
    result.round() as u64
}
