//! Number formatting utilities.

use std::time::Duration;

/// Format bytes per second as human-readable throughput.
pub fn format_throughput(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes_per_sec >= GB {
        format!("{:.1} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.1} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.1} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}

/// Format duration as human-readable latency.
pub fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();

    if nanos >= 1_000_000_000 {
        format!("{:.2} s", duration.as_secs_f64())
    } else if nanos >= 1_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else if nanos >= 1_000 {
        format!("{:.2} us", nanos as f64 / 1_000.0)
    } else {
        format!("{} ns", nanos)
    }
}

/// Format operations per second.
#[allow(dead_code)]
pub fn format_ops(ops_per_sec: f64) -> String {
    if ops_per_sec >= 1_000_000.0 {
        format!("{:.1}M ops/s", ops_per_sec / 1_000_000.0)
    } else if ops_per_sec >= 1_000.0 {
        format!("{:.1}k ops/s", ops_per_sec / 1_000.0)
    } else {
        format!("{:.0} ops/s", ops_per_sec)
    }
}

/// Format percentage difference.
pub fn format_percentage(ratio: f64) -> String {
    let pct = (ratio - 1.0) * 100.0;
    if pct >= 0.0 {
        format!("+{:.1}%", pct)
    } else {
        format!("{:.1}%", pct)
    }
}

/// Format mean ± standard deviation in hyperfine style.
/// Example: "2.45 ms ±  0.34 ms"
pub fn format_mean_sigma(mean: Duration, std_dev: Duration) -> String {
    format!("{} ± {}", format_duration(mean), format_duration(std_dev))
}

/// Format range (min … max) in hyperfine style.
/// Example: "1.89 ms …  3.21 ms"
pub fn format_range(min: Duration, max: Duration) -> String {
    format!("{} … {}", format_duration(min), format_duration(max))
}

/// Format speedup ratio with uncertainty.
/// Example: "1.45 ± 0.12"
pub fn format_speedup(ratio: f64, uncertainty: f64) -> String {
    format!("{:.2} ± {:.2}", ratio, uncertainty)
}

/// Format duration with right-aligned padding for table alignment.
/// Returns a fixed-width string suitable for columnar output.
pub fn format_duration_aligned(duration: Duration) -> String {
    let nanos = duration.as_nanos();

    if nanos >= 1_000_000_000 {
        format!("{:>7.2} s", duration.as_secs_f64())
    } else if nanos >= 1_000_000 {
        format!("{:>7.2} ms", nanos as f64 / 1_000_000.0)
    } else if nanos >= 1_000 {
        format!("{:>7.2} us", nanos as f64 / 1_000.0)
    } else {
        format!("{:>7} ns", nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_throughput() {
        assert_eq!(format_throughput(500.0), "500 B/s");
        assert_eq!(format_throughput(1500.0), "1.5 KB/s");
        assert_eq!(format_throughput(1_500_000.0), "1.4 MB/s");
        assert_eq!(format_throughput(1_500_000_000.0), "1.4 GB/s");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_nanos(500)), "500 ns");
        assert_eq!(format_duration(Duration::from_micros(500)), "500.00 us");
        assert_eq!(format_duration(Duration::from_millis(500)), "500.00 ms");
        assert_eq!(format_duration(Duration::from_secs(2)), "2.00 s");
    }

    #[test]
    fn test_format_mean_sigma() {
        let mean = Duration::from_micros(2450);
        let std_dev = Duration::from_micros(340);
        let result = format_mean_sigma(mean, std_dev);
        assert!(result.contains("±"));
        assert!(result.contains("ms") || result.contains("us"));
    }

    #[test]
    fn test_format_range() {
        let min = Duration::from_micros(1890);
        let max = Duration::from_micros(3210);
        let result = format_range(min, max);
        assert!(result.contains("…"));
    }

    #[test]
    fn test_format_speedup() {
        assert_eq!(format_speedup(1.45, 0.12), "1.45 ± 0.12");
        assert_eq!(format_speedup(2.0, 0.05), "2.00 ± 0.05");
    }
}
