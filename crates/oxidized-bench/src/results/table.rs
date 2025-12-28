//! Terminal table rendering using comfy-table.

use crate::config::{BenchmarkConfig, OperationType};
use crate::results::{format_duration, format_throughput, BenchmarkStats};
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
use std::io::Write;
use std::time::Duration;

/// Render a results table for a specific operation type.
pub fn render_results_table<W: Write>(
    writer: &mut W,
    operation: &OperationType,
    stats: &[&BenchmarkStats],
    config: &BenchmarkConfig,
) -> std::io::Result<()> {
    if stats.is_empty() {
        return Ok(());
    }

    // Print operation header
    let header = format!(" {} ", operation);
    if config.color {
        writeln!(writer, "\x1b[1;33m{:=^60}\x1b[0m", header)?;
    } else {
        writeln!(writer, "{:=^60}", header)?;
    }
    writeln!(writer)?;

    // Group by file size if applicable
    let has_sizes = stats.iter().any(|s| s.file_size.is_some());

    if has_sizes {
        // Group by file size
        let mut by_size: std::collections::HashMap<_, Vec<_>> = std::collections::HashMap::new();
        for stat in stats {
            by_size.entry(stat.file_size).or_default().push(*stat);
        }

        for (size, size_stats) in by_size {
            if let Some(s) = size {
                writeln!(writer, "File Size: {}", s)?;
            }
            render_comparison_table(writer, &size_stats, config)?;
            writeln!(writer)?;
        }
    } else {
        render_comparison_table(writer, stats, config)?;
    }

    Ok(())
}

/// Render a comparison table for a set of benchmark stats.
fn render_comparison_table<W: Write>(
    writer: &mut W,
    stats: &[&BenchmarkStats],
    config: &BenchmarkConfig,
) -> std::io::Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Build header row
    let mut header = vec![Cell::new("Metric").add_attribute(Attribute::Bold)];
    for stat in stats {
        let cell = if config.color {
            Cell::new(stat.implementation.name())
                .add_attribute(Attribute::Bold)
                .fg(implementation_color(&stat.implementation))
        } else {
            Cell::new(stat.implementation.name()).add_attribute(Attribute::Bold)
        };
        header.push(cell);
    }
    header.push(Cell::new("Winner").add_attribute(Attribute::Bold));
    table.set_header(header);

    // Throughput row (if applicable)
    if stats.iter().any(|s| s.throughput.is_some()) {
        let mut row = vec![Cell::new("Throughput")];
        let throughputs: Vec<_> = stats
            .iter()
            .map(|s| s.throughput.map(|t| t.bytes_per_sec).unwrap_or(0.0))
            .collect();
        let max_throughput = throughputs
            .iter()
            .cloned()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        for (i, stat) in stats.iter().enumerate() {
            let value = if let Some(t) = stat.throughput {
                format_throughput(t.bytes_per_sec)
            } else {
                "-".to_string()
            };

            let cell = if config.color && throughputs[i] == max_throughput && max_throughput > 0.0 {
                Cell::new(value).fg(Color::Green)
            } else {
                Cell::new(value)
            };
            row.push(cell);
        }

        // Winner
        let winner = stats
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                let a_t = a.throughput.map(|t| t.bytes_per_sec).unwrap_or(0.0);
                let b_t = b.throughput.map(|t| t.bytes_per_sec).unwrap_or(0.0);
                a_t.partial_cmp(&b_t).unwrap()
            })
            .map(|(_, s)| s.implementation.short_name());

        let winner_cell = if config.color {
            Cell::new(format!("{}", winner.unwrap_or("-"))).fg(Color::Green)
        } else {
            Cell::new(format!("{}", winner.unwrap_or("-")))
        };
        row.push(winner_cell);
        table.add_row(row);
    }

    // Latency rows
    let latency_metrics: &[(&str, fn(&BenchmarkStats) -> Duration)] = &[
        ("Mean Latency", |s: &BenchmarkStats| s.latency.mean),
        ("P50 Latency", |s: &BenchmarkStats| s.latency.p50),
        ("P95 Latency", |s: &BenchmarkStats| s.latency.p95),
        ("P99 Latency", |s: &BenchmarkStats| s.latency.p99),
    ];

    for (metric_name, extractor) in latency_metrics {
        let mut row = vec![Cell::new(metric_name)];
        let latencies: Vec<_> = stats.iter().map(|s| extractor(s)).collect();
        let min_latency = latencies.iter().min().copied();

        for (i, stat) in stats.iter().enumerate() {
            let value = format_duration(extractor(stat));
            let cell =
                if config.color && Some(latencies[i]) == min_latency && latencies[i].as_nanos() > 0
                {
                    Cell::new(value).fg(Color::Green)
                } else {
                    Cell::new(value)
                };
            row.push(cell);
        }

        // Winner (lowest latency)
        let winner = stats
            .iter()
            .min_by(|a, b| extractor(a).partial_cmp(&extractor(b)).unwrap())
            .map(|s| s.implementation.short_name());

        let winner_cell = if config.color {
            Cell::new(format!("{}", winner.unwrap_or("-"))).fg(Color::Green)
        } else {
            Cell::new(format!("{}", winner.unwrap_or("-")))
        };
        row.push(winner_cell);
        table.add_row(row);
    }

    // Std Dev row
    {
        let mut row = vec![Cell::new("Std Dev")];
        for stat in stats {
            row.push(Cell::new(format_duration(stat.latency.std_dev)));
        }
        row.push(Cell::new("-"));
        table.add_row(row);
    }

    // Sample count row
    {
        let mut row = vec![Cell::new("Samples")];
        for stat in stats {
            row.push(Cell::new(stat.sample_count.to_string()));
        }
        row.push(Cell::new("-"));
        table.add_row(row);
    }

    writeln!(writer, "{}", table)?;

    Ok(())
}

/// Get color for an implementation.
fn implementation_color(impl_type: &crate::config::Implementation) -> Color {
    use crate::config::Implementation;
    match impl_type {
        Implementation::OxidizedFuse => Color::Cyan,
        Implementation::OxidizedFsKit => Color::Magenta,
        Implementation::OfficialCryptomator => Color::Yellow,
    }
}
