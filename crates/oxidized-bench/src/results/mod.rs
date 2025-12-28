//! Results processing and visualization.

mod stats;
mod format;
mod table;
mod chart;

pub use stats::{BenchmarkStats, LatencyStats, Throughput, compute_stats};
pub use format::{format_duration, format_throughput, format_percentage};
pub use table::render_results_table;
pub use chart::render_bar_chart;

use crate::bench::BenchmarkResult;
use crate::config::{BenchmarkConfig, Implementation};
use std::io::Write;

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

    // Print summary
    render_summary(writer, &stats, config)?;

    Ok(())
}

/// Render the summary section.
fn render_summary<W: Write>(
    writer: &mut W,
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

    // Compare implementations pairwise
    writeln!(writer)?;
    let impls: Vec<_> = config.implementations.iter().collect();
    for i in 0..impls.len() {
        for j in (i + 1)..impls.len() {
            let impl_a = impls[i];
            let impl_b = impls[j];

            // Calculate average speedup
            let mut speedups = Vec::new();
            for benchmark_stats in by_benchmark.values() {
                let stat_a = benchmark_stats.iter().find(|s| s.implementation == *impl_a);
                let stat_b = benchmark_stats.iter().find(|s| s.implementation == *impl_b);

                if let (Some(a), Some(b)) = (stat_a, stat_b) {
                    let a_ns = a.latency.mean.as_nanos() as f64;
                    let b_ns = b.latency.mean.as_nanos() as f64;
                    if a_ns > 0.0 && b_ns > 0.0 {
                        speedups.push(a_ns / b_ns);
                    }
                }
            }

            if !speedups.is_empty() {
                let avg_speedup: f64 = speedups.iter().sum::<f64>() / speedups.len() as f64;
                let (faster, _slower, ratio) = if avg_speedup < 1.0 {
                    (impl_a, impl_b, 1.0 / avg_speedup)
                } else {
                    (impl_b, impl_a, avg_speedup)
                };

                let pct = (ratio - 1.0) * 100.0;
                writeln!(
                    writer,
                    "{} vs {}: {} is {:.1}% faster on average",
                    impl_a, impl_b, faster, pct
                )?;
            }
        }
    }

    writeln!(writer)?;

    Ok(())
}
