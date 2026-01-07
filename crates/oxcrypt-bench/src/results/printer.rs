//! Hyperfine-style benchmark result printer.

// Allow statistical calculations with casts
#![allow(clippy::cast_sign_loss)]

use crate::config::Implementation;
use crate::results::bayesian::BayesianComparison;
use crate::results::format::{format_duration, format_speedup, format_throughput};
use crate::results::stats::BenchmarkStats;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::time::Duration;

/// Aggregated statistics for a (benchmark_name, implementation) pair.
///
/// Used to combine multiple runs of the same benchmark/implementation for comparison.
#[derive(Debug, Clone)]
struct AggregatedStats {
    name: String,
    implementation: Implementation,
    mean: Duration,
    std_dev: Duration,
    sample_count: usize,
}

/// Aggregate stats by (benchmark_name, implementation) to combine multiple runs.
///
/// Uses weighted average for mean and pooled standard deviation for combining variances.
fn aggregate_stats(all_stats: &[BenchmarkStats]) -> Vec<AggregatedStats> {
    // Group by (name, implementation)
    let mut grouped: HashMap<(String, Implementation), Vec<&BenchmarkStats>> = HashMap::new();
    for stats in all_stats {
        grouped
            .entry((stats.name.clone(), stats.implementation))
            .or_default()
            .push(stats);
    }

    grouped
        .into_iter()
        .map(|((name, implementation), stats_list)| {
            if stats_list.len() == 1 {
                // Single entry, just convert
                let s = stats_list[0];
                AggregatedStats {
                    name,
                    implementation,
                    mean: s.latency.mean,
                    std_dev: s.latency.std_dev,
                    sample_count: s.sample_count,
                }
            } else {
                // Multiple entries - combine using weighted average
                let total_samples: usize = stats_list.iter().map(|s| s.sample_count).sum();

                // Weighted mean
                let weighted_mean_ns: f64 = stats_list
                    .iter()
                    .map(|s| s.latency.mean.as_nanos() as f64 * s.sample_count as f64)
                    .sum::<f64>()
                    / total_samples as f64;

                // Pooled standard deviation
                // σ_pooled = sqrt(Σ(n_i * (σ_i² + (μ_i - μ_pooled)²)) / Σn_i)
                let pooled_var: f64 = stats_list
                    .iter()
                    .map(|s| {
                        let var = (s.latency.std_dev.as_nanos() as f64).powi(2);
                        let mean_diff = s.latency.mean.as_nanos() as f64 - weighted_mean_ns;
                        s.sample_count as f64 * (var + mean_diff.powi(2))
                    })
                    .sum::<f64>()
                    / total_samples as f64;

                AggregatedStats {
                    name,
                    implementation,
                    mean: Duration::from_nanos(weighted_mean_ns as u64),
                    std_dev: Duration::from_nanos(pooled_var.sqrt() as u64),
                    sample_count: total_samples,
                }
            }
        })
        .collect()
}

/// Formats and prints benchmark results in hyperfine style.
pub struct BenchmarkPrinter {
    /// Whether color output is enabled.
    color: bool,
}

impl BenchmarkPrinter {
    /// Create a new printer.
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    /// Print a single benchmark result in hyperfine format.
    ///
    /// Example output:
    /// ```text
    /// Benchmark: fuse / read_4KB
    ///   Time (mean ± σ):     2.45 ms ±  0.34 ms    [Throughput: 125.3 MB/s]
    ///   Range (min … max):   1.89 ms …  3.21 ms    50 runs
    /// ```
    pub fn print_result(&self, stats: &BenchmarkStats) {
        let mean = format_duration(stats.latency.mean);
        let std_dev = format_duration(stats.latency.std_dev);
        let min = format_duration(stats.latency.min);
        let max = format_duration(stats.latency.max);

        // Throughput info if available
        let throughput_info = stats
            .throughput
            .map(|t| format!("[Throughput: {}]", format_throughput(t.bytes_per_sec)))
            .unwrap_or_default();

        if self.color {
            // Line 1: Time (mean ± σ)
            println!(
                "  {} ({} ± {}):  {} ± {}    {}",
                "Time".bold(),
                "mean".cyan(),
                "σ".cyan(),
                mean.cyan(),
                std_dev.cyan().dimmed(),
                throughput_info.dimmed()
            );

            // Line 2: Range (min … max)
            println!(
                "  {} ({} … {}):  {} … {}    {} runs",
                "Range".bold(),
                "min".green(),
                "max".yellow(),
                min.green(),
                max.yellow(),
                stats.sample_count
            );
        } else {
            println!(
                "  Time (mean ± σ):  {mean} ± {std_dev}    {throughput_info}"
            );
            println!(
                "  Range (min … max):  {} … {}    {} runs",
                min, max, stats.sample_count
            );
        }
        println!();
    }

    /// Print the final comparison summary in hyperfine style.
    ///
    /// Example output:
    /// ```text
    /// Summary
    ///   fuse / read_4KB ran
    ///     1.45 ± 0.12 times faster than webdav / read_4KB
    ///     2.31 ± 0.18 times faster than nfs / read_4KB
    /// ```
    pub fn print_summary(&self, all_stats: &[BenchmarkStats]) {
        // Aggregate stats by (benchmark_name, implementation) to combine multiple runs
        let aggregated = aggregate_stats(all_stats);

        // Group aggregated stats by benchmark name
        let mut by_benchmark: HashMap<String, Vec<AggregatedStats>> = HashMap::new();
        for stats in aggregated {
            by_benchmark
                .entry(stats.name.clone())
                .or_default()
                .push(stats);
        }

        // Only print summary if there are multiple implementations for some benchmark
        let has_comparisons = by_benchmark
            .values()
            .any(|v| v.iter().map(|s| s.implementation).collect::<std::collections::HashSet<_>>().len() > 1);
        if !has_comparisons {
            return;
        }

        println!();
        if self.color {
            println!("{}", "Summary".bold());
        } else {
            println!("Summary");
        }

        for (benchmark_name, stats) in &by_benchmark {
            // Filter out stats with zero runs (failed benchmarks)
            let valid_stats: Vec<_> = stats
                .iter()
                .filter(|s| s.mean.as_nanos() > 0 && s.sample_count > 0)
                .collect();

            // Check we have multiple distinct implementations
            let impl_set: std::collections::HashSet<_> = valid_stats.iter().map(|s| s.implementation).collect();
            if impl_set.len() < 2 {
                continue;
            }

            // Find the fastest implementation (lowest mean latency)
            // SAFETY: valid_stats has at least 2 elements (checked by impl_set.len() >= 2 above)
            let fastest = valid_stats
                .iter()
                .min_by(|a, b| a.mean.cmp(&b.mean))
                .expect("valid_stats is non-empty (checked above)");

            let fastest_name = format!("{} / {}", fastest.implementation.short_name(), benchmark_name);

            if self.color {
                println!("  {} ran", fastest_name.green().bold());
            } else {
                println!("  {fastest_name} ran");
            }

            // Get unique other implementations (deduplicated)
            let mut other_impls: Vec<_> = valid_stats
                .iter()
                .filter(|s| s.implementation != fastest.implementation)
                .collect();
            // Deduplicate by implementation (in case there are multiple - shouldn't happen after aggregation)
            other_impls.sort_by_key(|s| s.implementation.short_name());
            other_impls.dedup_by_key(|s| s.implementation.short_name());

            // Compare to other implementations
            let mut comparisons: Vec<_> = other_impls
                .into_iter()
                .filter_map(|other| {
                    let speedup = other.mean.as_nanos() as f64
                        / fastest.mean.as_nanos() as f64;
                    // Estimate uncertainty using Standard Error of the Mean (SEM = σ/√n)
                    // This gives tighter bounds that represent uncertainty in the mean,
                    // not the spread of individual samples.
                    let sem_fastest = fastest.std_dev.as_nanos() as f64
                        / (fastest.sample_count as f64).sqrt();
                    let sem_other = other.std_dev.as_nanos() as f64
                        / (other.sample_count as f64).sqrt();
                    let rel_err_fastest = sem_fastest / fastest.mean.as_nanos() as f64;
                    let rel_err_other = sem_other / other.mean.as_nanos() as f64;
                    let uncertainty = speedup * (rel_err_fastest.powi(2) + rel_err_other.powi(2)).sqrt();

                    // Skip comparisons with invalid values
                    if speedup.is_finite() && uncertainty.is_finite() {
                        Some((other, speedup, uncertainty))
                    } else {
                        None
                    }
                })
                .collect();

            // Sort by speedup (fastest comparisons first)
            comparisons.sort_by(|a, b| a.1.total_cmp(&b.1));

            for (other, speedup, uncertainty) in comparisons {
                let other_name = format!("{} / {}", other.implementation.short_name(), benchmark_name);
                let speedup_str = format_speedup(speedup, uncertainty);

                if self.color {
                    println!(
                        "    {} times faster than {}",
                        speedup_str.cyan(),
                        other_name
                    );
                } else {
                    println!("    {speedup_str} times faster than {other_name}");
                }
            }
        }
        println!();
    }

    /// Print a detailed summary using Bayesian comparisons.
    ///
    /// This version uses proper statistical analysis for more accurate uncertainty.
    #[allow(dead_code)]
    pub fn print_summary_bayesian(
        &self,
        all_stats: &[BenchmarkStats],
        comparisons: &[BayesianComparison],
    ) {
        // Group stats by benchmark name
        let mut by_benchmark: HashMap<String, Vec<&BenchmarkStats>> = HashMap::new();
        for stats in all_stats {
            by_benchmark
                .entry(stats.name.clone())
                .or_default()
                .push(stats);
        }

        // Only print summary if there are multiple implementations
        let has_comparisons = by_benchmark.values().any(|v| v.len() > 1);
        if !has_comparisons {
            return;
        }

        println!();
        if self.color {
            println!("{}", "Summary".bold());
        } else {
            println!("Summary");
        }

        for (benchmark_name, stats) in &by_benchmark {
            if stats.len() < 2 {
                continue;
            }

            // Find the fastest implementation
            // SAFETY: stats has at least 2 elements (checked by stats.len() >= 2 above)
            let fastest = stats
                .iter()
                .min_by(|a, b| a.latency.mean.cmp(&b.latency.mean))
                .expect("stats is non-empty (checked above)");

            let fastest_name = format!("{} / {}", fastest.implementation.short_name(), benchmark_name);

            if self.color {
                println!("  {} ran", fastest_name.green().bold());
            } else {
                println!("  {fastest_name} ran");
            }

            // Find relevant Bayesian comparisons for this benchmark
            for other in stats.iter().filter(|s| s.implementation != fastest.implementation) {
                let other_name = format!("{} / {}", other.implementation.short_name(), benchmark_name);

                // Try to find the Bayesian comparison for this pair
                let comparison = comparisons.iter().find(|c| {
                    (c.impl_a == fastest.implementation.name() && c.impl_b == other.implementation.name())
                        || (c.impl_b == fastest.implementation.name()
                            && c.impl_a == other.implementation.name())
                });

                if let Some(comp) = comparison {
                    // Use Bayesian credible interval
                    let (speedup, ci_low, ci_high) = if comp.impl_a == fastest.implementation.name() {
                        (comp.speedup_ratio, comp.speedup_ci_low, comp.speedup_ci_high)
                    } else {
                        // Invert the ratio
                        (
                            1.0 / comp.speedup_ratio,
                            1.0 / comp.speedup_ci_high,
                            1.0 / comp.speedup_ci_low,
                        )
                    };

                    // Calculate symmetric uncertainty from CI
                    let uncertainty = (ci_high - ci_low) / 4.0; // Approximate ±2σ

                    let speedup_str = format_speedup(speedup, uncertainty);
                    let significance = if comp.prob_equivalent > 0.9 {
                        " (not significant)"
                    } else if !comp.can_claim_a_faster() && !comp.can_claim_b_faster() {
                        " (low confidence)"
                    } else {
                        ""
                    };

                    if self.color {
                        println!(
                            "    {} times faster than {}{}",
                            speedup_str.cyan(),
                            other_name,
                            significance.dimmed()
                        );
                    } else {
                        println!(
                            "    {speedup_str} times faster than {other_name}{significance}"
                        );
                    }
                } else {
                    // Fallback to simple calculation
                    let speedup = other.latency.mean.as_nanos() as f64
                        / fastest.latency.mean.as_nanos() as f64;
                    let speedup_str = format!("{speedup:.2}x");

                    if self.color {
                        println!(
                            "    {} times faster than {}",
                            speedup_str.cyan(),
                            other_name
                        );
                    } else {
                        println!("    {speedup_str} times faster than {other_name}");
                    }
                }
            }
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileSize, Implementation, OperationType};
    use crate::results::stats::{LatencyStats, Throughput};
    use std::time::Duration;

    fn make_stats(name: &str, impl_type: Implementation, mean_ms: u64) -> BenchmarkStats {
        BenchmarkStats {
            name: name.to_string(),
            operation: OperationType::SequentialRead,
            implementation: impl_type,
            file_size: Some(FileSize::Tiny),
            sample_count: 50,
            throughput: Some(Throughput {
                bytes_per_sec: 125_000_000.0,
                ops_per_sec: 1000.0,
            }),
            latency: LatencyStats {
                mean: Duration::from_millis(mean_ms),
                std_dev: Duration::from_micros(mean_ms * 100),
                min: Duration::from_millis(mean_ms - 1),
                max: Duration::from_millis(mean_ms + 1),
                p50: Duration::from_millis(mean_ms),
                p95: Duration::from_millis(mean_ms + 1),
                p99: Duration::from_millis(mean_ms + 1),
            },
        }
    }

    #[test]
    fn test_print_result_no_panic() {
        let printer = BenchmarkPrinter::new(false);
        let stats = make_stats("read_1KB", Implementation::OxidizedFuse, 5);
        printer.print_result(&stats);
    }

    #[test]
    fn test_print_summary_single_impl() {
        let printer = BenchmarkPrinter::new(false);
        let stats = vec![make_stats("read_1KB", Implementation::OxidizedFuse, 5)];
        // Should not panic with single implementation
        printer.print_summary(&stats);
    }

    #[test]
    fn test_print_summary_multiple_impls() {
        let printer = BenchmarkPrinter::new(false);
        let stats = vec![
            make_stats("read_1KB", Implementation::OxidizedFuse, 5),
            make_stats("read_1KB", Implementation::OxidizedWebDav, 10),
        ];
        printer.print_summary(&stats);
    }
}
