//! Unicode bar chart rendering.

use crate::config::BenchmarkConfig;
use crate::results::{format_throughput, BenchmarkStats};
use std::io::Write;

/// Characters for bar chart rendering.
const BAR_FULL: char = '█';
const BAR_PARTIAL: &[char] = &['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];

/// Maximum width for bar charts.
const MAX_BAR_WIDTH: usize = 50;

/// Render a bar chart comparing throughput across implementations.
pub fn render_bar_chart<W: Write>(
    writer: &mut W,
    stats: &[&BenchmarkStats],
    config: &BenchmarkConfig,
) -> std::io::Result<()> {
    // Filter to stats with throughput
    let stats_with_throughput: Vec<_> = stats
        .iter()
        .filter(|s| s.throughput.is_some())
        .copied()
        .collect();

    if stats_with_throughput.is_empty() {
        return Ok(());
    }

    // Find maximum throughput for scaling
    let max_throughput = stats_with_throughput
        .iter()
        .filter_map(|s| s.throughput.map(|t| t.bytes_per_sec))
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(1.0);

    // Sort by throughput (highest first)
    let mut sorted_stats = stats_with_throughput;
    sorted_stats.sort_by(|a, b| {
        let a_t = a.throughput.map(|t| t.bytes_per_sec).unwrap_or(0.0);
        let b_t = b.throughput.map(|t| t.bytes_per_sec).unwrap_or(0.0);
        b_t.partial_cmp(&a_t).unwrap()
    });

    // Print header
    if config.color {
        writeln!(writer, "\x1b[1;34mThroughput Comparison:\x1b[0m")?;
    } else {
        writeln!(writer, "Throughput Comparison:")?;
    }

    // Find longest implementation name for alignment
    let max_name_len = sorted_stats
        .iter()
        .map(|s| s.implementation.name().len())
        .max()
        .unwrap_or(10);

    // Render bars
    for stat in &sorted_stats {
        let throughput = stat.throughput.map(|t| t.bytes_per_sec).unwrap_or(0.0);
        let ratio = throughput / max_throughput;
        let percentage = (ratio * 100.0) as u32;

        let bar = render_bar(ratio, MAX_BAR_WIDTH);
        let throughput_str = format_throughput(throughput);

        let name = format!("{:>width$}", stat.implementation.name(), width = max_name_len);

        if config.color {
            let color = implementation_ansi_color(&stat.implementation);
            writeln!(
                writer,
                "{} │{}│ {} ({}%)",
                name, color_bar(&bar, color), throughput_str, percentage
            )?;
        } else {
            writeln!(
                writer,
                "{} │{}│ {} ({}%)",
                name, bar, throughput_str, percentage
            )?;
        }
    }

    Ok(())
}

/// Render a progress bar string.
fn render_bar(ratio: f64, width: usize) -> String {
    let filled = ratio * width as f64;
    let full_blocks = filled as usize;
    let partial_idx = ((filled - full_blocks as f64) * 8.0) as usize;

    let mut bar = String::with_capacity(width);

    // Full blocks
    for _ in 0..full_blocks {
        bar.push(BAR_FULL);
    }

    // Partial block
    if full_blocks < width && partial_idx > 0 {
        bar.push(BAR_PARTIAL[partial_idx.min(7)]);
    }

    // Padding
    while bar.chars().count() < width {
        bar.push(' ');
    }

    bar
}

/// Wrap bar in ANSI color codes.
fn color_bar(bar: &str, color: &str) -> String {
    format!("{}{}\x1b[0m", color, bar)
}

/// Get ANSI color code for an implementation.
fn implementation_ansi_color(impl_type: &crate::config::Implementation) -> &'static str {
    use crate::config::Implementation;
    match impl_type {
        Implementation::OxidizedFuse => "\x1b[36m",     // Cyan
        Implementation::OxidizedFsKit => "\x1b[35m",    // Magenta
        Implementation::OfficialCryptomator => "\x1b[33m", // Yellow
    }
}

/// Render a latency comparison bar chart (lower is better).
#[allow(dead_code)]
pub fn render_latency_chart<W: Write>(
    writer: &mut W,
    stats: &[&BenchmarkStats],
    config: &BenchmarkConfig,
) -> std::io::Result<()> {
    if stats.is_empty() {
        return Ok(());
    }

    // Find maximum latency for scaling
    let max_latency = stats
        .iter()
        .map(|s| s.latency.mean.as_nanos())
        .max()
        .unwrap_or(1) as f64;

    // Sort by latency (lowest first - best)
    let mut sorted_stats: Vec<_> = stats.to_vec();
    sorted_stats.sort_by(|a, b| a.latency.mean.cmp(&b.latency.mean));

    // Print header
    if config.color {
        writeln!(writer, "\x1b[1;34mLatency Comparison (lower is better):\x1b[0m")?;
    } else {
        writeln!(writer, "Latency Comparison (lower is better):")?;
    }

    // Find longest implementation name for alignment
    let max_name_len = sorted_stats
        .iter()
        .map(|s| s.implementation.name().len())
        .max()
        .unwrap_or(10);

    // Render bars
    for stat in &sorted_stats {
        let latency_ns = stat.latency.mean.as_nanos() as f64;
        let ratio = latency_ns / max_latency;

        let bar = render_bar(ratio, MAX_BAR_WIDTH);
        let latency_str = crate::results::format_duration(stat.latency.mean);

        let name = format!("{:>width$}", stat.implementation.name(), width = max_name_len);

        if config.color {
            let color = implementation_ansi_color(&stat.implementation);
            writeln!(writer, "{} │{}│ {}", name, color_bar(&bar, color), latency_str)?;
        } else {
            writeln!(writer, "{} │{}│ {}", name, bar, latency_str)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_bar() {
        let bar = render_bar(1.0, 10);
        assert_eq!(bar.chars().count(), 10);
        assert!(bar.chars().all(|c| c == BAR_FULL));

        let bar = render_bar(0.5, 10);
        assert_eq!(bar.chars().count(), 10);

        let bar = render_bar(0.0, 10);
        assert_eq!(bar.chars().count(), 10);
        assert!(bar.chars().all(|c| c == ' '));
    }
}
