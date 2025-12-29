//! Results processing and visualization.

mod bayesian;
mod chart;
mod format;
mod stats;
mod table;

pub use bayesian::{bayesian_compare, BayesianComparison, BayesianConfig};
pub use chart::render_bar_chart;
pub use format::{format_duration, format_percentage, format_throughput};
pub use stats::{compute_stats, BenchmarkStats, LatencyStats, Throughput};
pub use table::render_results_table;

use crate::bench::BenchmarkResult;
use crate::config::{BenchmarkConfig, Implementation};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

/// Generate and display the benchmark report.
pub fn generate_report<W: Write>(
    writer: &mut W,
    results: &[BenchmarkResult],
    config: &BenchmarkConfig,
) -> std::io::Result<()> {
    // Compute statistics for all results
    let stats: Vec<BenchmarkStats> = results.iter().map(compute_stats).collect();

    // Print header
    writeln!(writer)?;
    if config.color {
        writeln!(
            writer,
            "\x1b[1;36m{:=^80}\x1b[0m",
            " FILESYSTEM BENCHMARK COMPARISON "
        )?;
    } else {
        writeln!(writer, "{:=^80}", " FILESYSTEM BENCHMARK COMPARISON ")?;
    }
    writeln!(writer)?;

    // Print configuration
    writeln!(writer, "Suite: {}", config.suite)?;
    writeln!(writer, "Iterations: {}", config.effective_iterations())?;
    writeln!(
        writer,
        "Implementations: {}",
        config
            .implementations
            .iter()
            .map(|i| i.name())
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(writer)?;

    // Group results by operation type
    let mut grouped = std::collections::HashMap::new();
    for stat in &stats {
        grouped
            .entry(&stat.operation)
            .or_insert_with(Vec::new)
            .push(stat);
    }

    // Render tables for each operation group
    for (operation, operation_stats) in grouped {
        render_results_table(writer, operation, &operation_stats, config)?;
        writeln!(writer)?;

        // Render bar chart for throughput comparison
        if operation_stats.iter().any(|s| s.throughput.is_some()) {
            render_bar_chart(writer, &operation_stats, config)?;
            writeln!(writer)?;
        }
    }

    // Print summary with Bayesian analysis
    render_summary(writer, results, &stats, config)?;

    Ok(())
}

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
}

impl From<(&BenchmarkStats, &[std::time::Duration])> for BenchmarkStatsJson {
    fn from((stats, samples): (&BenchmarkStats, &[std::time::Duration])) -> Self {
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
        .map(|(result, stat)| BenchmarkStatsJson::from((stat, result.samples.as_slice())))
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
        },
        results: stats_json,
        comparisons,
    };

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, json)?;

    Ok(())
}

/// Render the summary section with Bayesian analysis.
fn render_summary<W: Write>(
    writer: &mut W,
    results: &[BenchmarkResult],
    stats: &[BenchmarkStats],
    config: &BenchmarkConfig,
) -> std::io::Result<()> {
    // Count wins per implementation
    let mut wins: std::collections::HashMap<Implementation, usize> = std::collections::HashMap::new();

    // Group by benchmark name for comparison
    let mut by_benchmark: std::collections::HashMap<String, Vec<&BenchmarkStats>> =
        std::collections::HashMap::new();
    for stat in stats {
        by_benchmark
            .entry(stat.name.clone())
            .or_default()
            .push(stat);
    }

    // Determine winner for each benchmark (lowest mean latency)
    for benchmark_stats in by_benchmark.values() {
        if benchmark_stats.len() > 1 {
            let winner = benchmark_stats
                .iter()
                .min_by(|a, b| a.latency.mean.partial_cmp(&b.latency.mean).unwrap())
                .map(|s| s.implementation);

            if let Some(w) = winner {
                *wins.entry(w).or_insert(0) += 1;
            }
        }
    }

    // Print summary box
    let total_tests = by_benchmark.len();

    if config.color {
        writeln!(writer, "\x1b[1;36m{:-^80}\x1b[0m", " SUMMARY ")?;
    } else {
        writeln!(writer, "{:-^80}", " SUMMARY ")?;
    }

    if let Some((overall_winner, count)) = wins.iter().max_by_key(|(_, c)| *c) {
        if config.color {
            writeln!(
                writer,
                "Overall Winner: \x1b[1;32m{}\x1b[0m (fastest in {}/{} benchmarks)",
                overall_winner, count, total_tests
            )?;
        } else {
            writeln!(
                writer,
                "Overall Winner: {} (fastest in {}/{} benchmarks)",
                overall_winner, count, total_tests
            )?;
        }
    }

    writeln!(writer)?;

    // --- Bayesian Analysis ---
    let bayesian_config = BayesianConfig::default();
    let comparisons = generate_bayesian_comparisons(results, &bayesian_config);

    if !comparisons.is_empty() {
        if config.color {
            writeln!(writer, "\x1b[1;36m{:-^80}\x1b[0m", " BAYESIAN ANALYSIS ")?;
        } else {
            writeln!(writer, "{:-^80}", " BAYESIAN ANALYSIS ")?;
        }
        writeln!(writer)?;

        // Group comparisons by implementation pair (aggregate across benchmarks)
        let mut pair_comparisons: std::collections::HashMap<
            (String, String),
            Vec<&BayesianComparison>,
        > = std::collections::HashMap::new();

        for comp in &comparisons {
            let key = if comp.impl_a < comp.impl_b {
                (comp.impl_a.clone(), comp.impl_b.clone())
            } else {
                (comp.impl_b.clone(), comp.impl_a.clone())
            };
            pair_comparisons.entry(key).or_default().push(comp);
        }

        for ((impl_a, impl_b), comps) in pair_comparisons {
            // Compute aggregate statistics across all benchmarks for this pair
            let avg_prob_a_faster: f64 =
                comps.iter().map(|c| c.prob_a_faster).sum::<f64>() / comps.len() as f64;
            let avg_speedup: f64 =
                comps.iter().map(|c| c.speedup_ratio).sum::<f64>() / comps.len() as f64;
            let min_speedup_ci: f64 = comps
                .iter()
                .map(|c| c.speedup_ci_low)
                .fold(f64::INFINITY, f64::min);
            let max_speedup_ci: f64 = comps
                .iter()
                .map(|c| c.speedup_ci_high)
                .fold(f64::NEG_INFINITY, f64::max);
            let avg_prob_practically_faster: f64 =
                comps.iter().map(|c| c.prob_practically_faster).sum::<f64>() / comps.len() as f64;
            let avg_prob_equivalent: f64 =
                comps.iter().map(|c| c.prob_equivalent).sum::<f64>() / comps.len() as f64;

            // Count how many benchmarks show high confidence
            let confident_a_wins = comps.iter().filter(|c| c.can_claim_a_faster()).count();
            let confident_b_wins = comps.iter().filter(|c| c.can_claim_b_faster()).count();

            // Determine winner for display
            let (winner, _loser, prob_faster, speedup_display) = if avg_prob_a_faster > 0.5 {
                (
                    &impl_a,
                    &impl_b,
                    avg_prob_a_faster,
                    avg_speedup,
                )
            } else {
                (
                    &impl_b,
                    &impl_a,
                    1.0 - avg_prob_a_faster,
                    1.0 / avg_speedup,
                )
            };

            writeln!(writer, "{} vs {}:", impl_a, impl_b)?;

            // Probability statement
            if config.color {
                let color = if prob_faster > 0.95 {
                    "\x1b[1;32m" // Green for high confidence
                } else if prob_faster > 0.80 {
                    "\x1b[1;33m" // Yellow for moderate
                } else {
                    "\x1b[0m" // Normal
                };
                writeln!(
                    writer,
                    "  P({} faster):    {}{:.1}%\x1b[0m",
                    winner,
                    color,
                    prob_faster * 100.0
                )?;
            } else {
                writeln!(
                    writer,
                    "  P({} faster):    {:.1}%",
                    winner,
                    prob_faster * 100.0
                )?;
            }

            // ROPE analysis
            writeln!(
                writer,
                "  P(>5% faster):       {:.1}%",
                avg_prob_practically_faster * 100.0
            )?;
            writeln!(
                writer,
                "  P(equivalent):       {:.1}%",
                avg_prob_equivalent * 100.0
            )?;

            // Speedup with CI
            writeln!(
                writer,
                "  Speedup:             {:.2}x [{:.2}x - {:.2}x]",
                speedup_display, min_speedup_ci, max_speedup_ci
            )?;

            // High-confidence wins count
            writeln!(
                writer,
                "  High-confidence wins: {} vs {}",
                if avg_prob_a_faster > 0.5 {
                    confident_a_wins
                } else {
                    confident_b_wins
                },
                if avg_prob_a_faster > 0.5 {
                    confident_b_wins
                } else {
                    confident_a_wins
                }
            )?;

            // Assessment
            let assessment = if avg_prob_equivalent > 0.8 {
                "Practically equivalent"
            } else if prob_faster > 0.95 && avg_prob_practically_faster > 0.80 {
                "Faster with high confidence"
            } else if prob_faster > 0.80 {
                "Likely faster (moderate confidence)"
            } else {
                "Difference not statistically significant"
            };

            if config.color {
                let (icon, color) = if assessment.contains("high confidence") {
                    ("\x1b[32m+\x1b[0m", "\x1b[1;32m")
                } else if assessment.contains("equivalent") {
                    ("\x1b[33m~\x1b[0m", "\x1b[33m")
                } else if assessment.contains("Likely") {
                    ("\x1b[33m?\x1b[0m", "\x1b[33m")
                } else {
                    ("\x1b[31m-\x1b[0m", "\x1b[31m")
                };
                writeln!(
                    writer,
                    "  {} {}{}: {}\x1b[0m",
                    icon, color, winner, assessment
                )?;
            } else {
                writeln!(writer, "  Assessment: {} - {}", winner, assessment)?;
            }

            writeln!(writer)?;
        }
    }

    // Interpretation guide
    if config.color {
        writeln!(writer, "\x1b[90m{:-^80}\x1b[0m", " INTERPRETATION ")?;
        writeln!(writer, "\x1b[90m")?;
    } else {
        writeln!(writer, "{:-^80}", " INTERPRETATION ")?;
    }
    writeln!(writer, "P(A faster):     Probability A has lower latency than B")?;
    writeln!(writer, "P(>5% faster):   Probability of >5% practical difference (ROPE)")?;
    writeln!(writer, "P(equivalent):   Probability difference is negligible")?;
    writeln!(writer, "Speedup:         Latency ratio with 95% credible interval")?;
    writeln!(writer)?;
    writeln!(writer, "Confidence levels:")?;
    writeln!(writer, "  >95% + >80% practical: High confidence claim")?;
    writeln!(writer, "  80-95%:                Moderate confidence")?;
    writeln!(writer, "  <80%:                  Not statistically significant")?;
    if config.color {
        writeln!(writer, "\x1b[0m")?;
    }

    writeln!(writer)?;

    Ok(())
}
