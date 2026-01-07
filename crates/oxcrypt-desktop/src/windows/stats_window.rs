//! Standalone Statistics Window
//!
//! This is a separate window component that runs in its own VirtualDom.
//! It displays real-time vault activity statistics with throughput plots.

use dioxus::prelude::*;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::backend::{mount_manager, ActivityStatus, SchedulerStatsSnapshot, VaultStats};
use crate::state::ThemePreference;

/// Number of samples to keep in history (120 samples * 500ms = 60 seconds)
const HISTORY_SAMPLES: usize = 120;

/// Sample interval in milliseconds
const SAMPLE_INTERVAL_MS: u64 = 500;

/// EMA smoothing factor (0.25 = ~2 second time constant, responsive but smooth)
const EMA_ALPHA: f64 = 0.25;

/// A single throughput sample with timestamp
#[derive(Clone, Copy, Debug)]
struct ThroughputSample {
    read_rate: f64,  // smoothed bytes per second
    write_rate: f64, // smoothed bytes per second
    timestamp: Instant,
}

/// Ring buffer for throughput history with EMA smoothing
#[derive(Clone, Debug)]
struct ThroughputHistory {
    samples: VecDeque<ThroughputSample>,
    prev_bytes_read: u64,
    prev_bytes_written: u64,
    prev_timestamp: Option<Instant>,
    /// Exponential moving average for read rate
    smoothed_read: f64,
    /// Exponential moving average for write rate
    smoothed_write: f64,
}

impl Default for ThroughputHistory {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(HISTORY_SAMPLES),
            prev_bytes_read: 0,
            prev_bytes_written: 0,
            prev_timestamp: None,
            smoothed_read: 0.0,
            smoothed_write: 0.0,
        }
    }
}

impl ThroughputHistory {
    /// Record a new sample and return the smoothed rates
    fn record(&mut self, bytes_read: u64, bytes_written: u64) -> (f64, f64) {
        let now = Instant::now();

        // Calculate instantaneous rates
        let (instant_read, instant_write) = if let Some(prev_time) = self.prev_timestamp {
            let elapsed = prev_time.elapsed().as_secs_f64().max(0.001);
            let read_delta = bytes_read.saturating_sub(self.prev_bytes_read);
            let write_delta = bytes_written.saturating_sub(self.prev_bytes_written);
            (read_delta as f64 / elapsed, write_delta as f64 / elapsed)
        } else {
            (0.0, 0.0)
        };

        // Update previous values
        self.prev_bytes_read = bytes_read;
        self.prev_bytes_written = bytes_written;
        self.prev_timestamp = Some(now);

        // Apply exponential moving average smoothing
        // EMA formula: smoothed = alpha * current + (1 - alpha) * previous
        if self.samples.is_empty() {
            // First sample - initialize EMA directly
            self.smoothed_read = instant_read;
            self.smoothed_write = instant_write;
        } else {
            self.smoothed_read = EMA_ALPHA * instant_read + (1.0 - EMA_ALPHA) * self.smoothed_read;
            self.smoothed_write = EMA_ALPHA * instant_write + (1.0 - EMA_ALPHA) * self.smoothed_write;
        }

        // Add smoothed sample to history
        let sample = ThroughputSample {
            read_rate: self.smoothed_read,
            write_rate: self.smoothed_write,
            timestamp: now,
        };

        if self.samples.len() >= HISTORY_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);

        (self.smoothed_read, self.smoothed_write)
    }

    /// Get the maximum rate in the history for scaling
    fn max_rate(&self) -> f64 {
        self.samples
            .iter()
            .flat_map(|s| [s.read_rate, s.write_rate])
            .fold(0.0_f64, f64::max)
            .max(1024.0) // Minimum 1 KB/s scale
    }
}

/// Chart color scheme for light/dark themes
struct ChartColors {
    background: &'static str,
    text: &'static str,
    read_line: &'static str,
    read_fill: &'static str,
    write_line: &'static str,
    write_fill: &'static str,
}

impl ChartColors {
    fn light() -> Self {
        Self {
            background: "#f3f4f6",  // gray-100
            text: "#6b7280",        // gray-500
            read_line: "#3b82f6",   // blue-500
            read_fill: "#3b82f620", // blue-500 with alpha
            write_line: "#f59e0b",  // amber-500
            write_fill: "#f59e0b20", // amber-500 with alpha
        }
    }

    fn dark() -> Self {
        Self {
            background: "#1f2937",  // gray-800
            text: "#d1d5db",        // gray-300 (lighter for better contrast)
            read_line: "#60a5fa",   // blue-400
            read_fill: "#60a5fa30", // blue-400 with alpha
            write_line: "#fbbf24",  // amber-400
            write_fill: "#fbbf2430", // amber-400 with alpha
        }
    }
}

/// Parse a hex color string to RGB tuple
fn parse_hex_color(hex: &str) -> (u8, u8, u8) {
    let hex = hex.trim_start_matches('#');
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
    (r, g, b)
}

/// Parse a hex color with alpha to RGBA tuple
fn parse_hex_color_alpha(hex: &str) -> (u8, u8, u8, f64) {
    let hex = hex.trim_start_matches('#');
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
    let a = if hex.len() >= 8 {
        f64::from(u8::from_str_radix(&hex[6..8], 16).unwrap_or(255)) / 255.0
    } else {
        1.0
    };
    (r, g, b, a)
}

/// Render throughput chart as SVG string
fn render_throughput_chart(history: &ThroughputHistory, is_dark: bool, width: u32, height: u32) -> String {
    use plotters::prelude::*;

    let colors = if is_dark {
        ChartColors::dark()
    } else {
        ChartColors::light()
    };

    let mut svg_buffer = String::new();
    {
        let root = SVGBackend::with_string(&mut svg_buffer, (width, height)).into_drawing_area();

        let bg = parse_hex_color(colors.background);
        root.fill(&RGBColor(bg.0, bg.1, bg.2)).ok();

        let max_rate = history.max_rate();
        let samples = &history.samples;

        // Time range: last 60 seconds (or less if not enough samples)
        let x_range = 0.0..60.0_f64;
        let y_range = 0.0..max_rate;

        let text_color = parse_hex_color(colors.text);

        let mut chart = ChartBuilder::on(&root)
            .margin(8)
            .x_label_area_size(22)
            .y_label_area_size(45)
            .build_cartesian_2d(x_range, y_range)
            .unwrap();

        chart
            .configure_mesh()
            .disable_mesh() // No grid lines - cleaner look
            .x_labels(5)
            .y_labels(4)
            .y_desc("")
            .axis_style(RGBColor(text_color.0, text_color.1, text_color.2))
            .label_style(("sans-serif", 12, &RGBColor(text_color.0, text_color.1, text_color.2)))
            .x_label_formatter(&|x| {
                // x=0 is 60s ago, x=60 is now
                // x is always in [0, 60] range, safe to cast to i32
                #[allow(clippy::cast_possible_truncation)]
                let secs_ago = (60.0 - x).round() as i32;
                if secs_ago == 0 {
                    "now".to_string()
                } else {
                    format!("{secs_ago}s")
                }
            })
            .y_label_formatter(&|y| format_rate_short(*y))
            .draw()
            .ok();

        // Convert samples to chart data points
        // x-axis: seconds ago (60 = oldest, 0 = newest)
        let now = Instant::now();

        if !samples.is_empty() {
            // Read throughput (area + line)
            let read_data: Vec<(f64, f64)> = samples
                .iter()
                .map(|s| {
                    let secs_ago = now.duration_since(s.timestamp).as_secs_f64();
                    (60.0 - secs_ago.min(60.0), s.read_rate)
                })
                .collect();

            let read_fill = parse_hex_color_alpha(colors.read_fill);
            let read_line_color = parse_hex_color(colors.read_line);

            // Draw filled area for reads
            chart
                .draw_series(AreaSeries::new(
                    read_data.iter().copied(),
                    0.0,
                    RGBAColor(read_fill.0, read_fill.1, read_fill.2, read_fill.3),
                ))
                .ok();

            // Draw line for reads
            chart
                .draw_series(LineSeries::new(
                    read_data.iter().copied(),
                    ShapeStyle::from(&RGBColor(read_line_color.0, read_line_color.1, read_line_color.2))
                        .stroke_width(2),
                ))
                .ok();

            // Write throughput (area + line)
            let write_data: Vec<(f64, f64)> = samples
                .iter()
                .map(|s| {
                    let secs_ago = now.duration_since(s.timestamp).as_secs_f64();
                    (60.0 - secs_ago.min(60.0), s.write_rate)
                })
                .collect();

            let write_fill = parse_hex_color_alpha(colors.write_fill);
            let write_line_color = parse_hex_color(colors.write_line);

            // Draw filled area for writes
            chart
                .draw_series(AreaSeries::new(
                    write_data.iter().copied(),
                    0.0,
                    RGBAColor(write_fill.0, write_fill.1, write_fill.2, write_fill.3),
                ))
                .ok();

            // Draw line for writes
            chart
                .draw_series(LineSeries::new(
                    write_data.iter().copied(),
                    ShapeStyle::from(&RGBColor(write_line_color.0, write_line_color.1, write_line_color.2))
                        .stroke_width(2),
                ))
                .ok();
        }

        root.present().ok();
    }

    make_svg_responsive(svg_buffer, width, height)
}

fn make_svg_responsive(svg: String, width: u32, height: u32) -> String {
    let needle = format!("width=\"{width}\" height=\"{height}\"");
    if svg.contains(&needle) {
        svg.replace(
            &needle,
            &format!(
                "viewBox=\"0 0 {width} {height}\" width=\"100%\" height=\"100%\" preserveAspectRatio=\"xMidYMid meet\""
            ),
        )
    } else {
        svg
    }
}

/// Format rate for Y-axis labels (compact)
fn format_rate_short(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        "0".to_string()
    } else if bytes_per_sec < 1024.0 {
        format!("{bytes_per_sec:.0}B")
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.0}K", bytes_per_sec / 1024.0)
    } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1}M", bytes_per_sec / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Standalone statistics window component
///
/// This component manages its own state and auto-refreshes statistics.
/// It's designed to run in a separate VirtualDom via `window.new_window()`.
#[component]
pub fn StatsWindow(vault_id: String, vault_name: String) -> Element {
    // Load config from disk (this is a standalone window)
    let config = use_signal(crate::state::AppConfig::load);

    // Get theme class for styling
    let theme = config.read().theme;
    let theme_class = theme.css_class().unwrap_or("");
    let platform_class = crate::current_platform().css_class();

    // Determine if we're in dark mode
    let is_dark = matches!(theme, ThemePreference::Dark | ThemePreference::System);

    // Get stats from mount manager
    let stats = mount_manager().get_stats(&vault_id);
    let scheduler_stats = mount_manager().get_scheduler_stats(&vault_id);

    // Throughput history for chart
    let mut history = use_signal(ThroughputHistory::default);

    // Auto-refresh stats every 500ms
    let mut refresh_counter = use_signal(|| 0u32);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_millis(SAMPLE_INTERVAL_MS)).await;
            refresh_counter.with_mut(|c| *c = c.wrapping_add(1));
        }
    });

    // Force re-render on counter change
    let _ = refresh_counter();

    rsx! {
        // Include Tailwind CSS
        document::Link { rel: "stylesheet", href: asset!("/assets/tailwind.css") }

        div {
            class: "min-h-screen bg-white dark:bg-neutral-900 {theme_class} {platform_class}",
            style: "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;",

            // Header (draggable title bar area)
            div {
                class: "px-6 pt-5 pb-4 border-b border-gray-200 dark:border-neutral-700",
                style: "-webkit-app-region: drag;",

                div {
                    class: "flex items-center gap-3",
                    span { class: "text-2xl", "📊" }
                    div {
                        h1 {
                            class: "text-lg font-semibold text-gray-900 dark:text-white",
                            "Vault Statistics"
                        }
                        p {
                            class: "text-sm text-gray-600 dark:text-gray-300",
                            "{vault_name}"
                        }
                    }
                }
            }

            // Content
            div {
                class: "px-6 py-5 overflow-y-auto",
                style: "max-height: calc(100vh - 80px);",

                if let Some(stats) = &stats {
                    {StatsContent(stats, scheduler_stats.as_ref(), &mut history, is_dark)}
                } else {
                    div {
                        class: "text-center py-8 text-gray-600 dark:text-gray-300",
                        "Statistics not available for this vault."
                    }
                }
            }
        }
    }
}

/// Stats content - extracts data from Arc<VaultStats> and renders UI
#[allow(non_snake_case)]
fn StatsContent(
    stats: &Arc<VaultStats>,
    scheduler_stats: Option<&SchedulerStatsSnapshot>,
    history: &mut Signal<ThroughputHistory>,
    is_dark: bool,
) -> Element {
    // Extract current values
    let activity = stats.activity_status(Duration::from_secs(3));
    let session_duration = stats.session_duration();
    let bytes_read = stats.bytes_read();
    let bytes_written = stats.bytes_written();

    // Get latency from stats
    let read_latency_ms = stats.avg_read_latency_ms();
    let write_latency_ms = stats.avg_write_latency_ms();

    // Metadata stats
    let metadata_ops = stats.metadata_op_count();
    let metadata_latency_ms = stats.avg_metadata_latency_ms();

    // Error stats
    let error_count = stats.error_count();

    // Operation counts for breakdown
    let total_reads = stats.read_count();
    let total_writes = stats.write_count();
    let open_files = stats.open_file_count();
    let open_dirs = stats.open_dir_count();

    // Cache stats
    let cache = stats.cache_stats();
    let hit_rate = cache.hit_rate();
    let hits = cache.hit_count();
    let misses = cache.miss_count();

    // Record sample and get current rates
    let (read_rate, write_rate) = history.write().record(bytes_read, bytes_written);

    // Render chart SVG (responsive via viewBox, higher base size for crispness)
    let chart_svg = render_throughput_chart(&history.read(), is_dark, 640, 260);

    rsx! {
        div {
            class: "grid",
            style: "grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); column-gap: 20px; row-gap: 20px;",

            div {
                class: "flex items-center justify-between",
                style: "grid-column: 1 / -1; gap: 16px;",
                div {
                    class: "flex items-center gap-3",
                    ActivityBadge { status: activity }
                    if error_count > 0 {
                        ErrorBadge { count: error_count }
                    }
                }
                span {
                    class: "text-sm text-gray-600 dark:text-gray-300",
                    "Session: {format_duration(session_duration)}"
                }
            }

            // Left column
            div {
                class: "flex flex-col",
                style: "row-gap: 16px;",
                // Read/Write Performance Cards
                div {
                    class: "grid",
                    style: "grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px;",

                    // Read Stats Card
                    ThroughputCard {
                        label: "READ",
                        rate: read_rate,
                        latency_ms: read_latency_ms,
                        icon: "📖",
                    }

                    // Write Stats Card
                    ThroughputCard {
                        label: "WRITE",
                        rate: write_rate,
                        latency_ms: write_latency_ms,
                        icon: "✏️",
                    }
                }

                // Operations Grid (reads, writes, metadata, open handles)
                div {
                    class: "grid",
                    style: "grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px;",

                    OperationCounter { label: "Reads", count: total_reads, icon: "📖" }
                    OperationCounter { label: "Writes", count: total_writes, icon: "✏️" }
                    OperationCounter { label: "Metadata", count: metadata_ops, icon: "📋" }
                    div {
                        class: "bg-gray-100 dark:bg-gray-800 rounded-lg p-2 text-center",
                        span {
                            class: "text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide",
                            "🔓 Open"
                        }
                        p {
                            class: "text-sm font-semibold text-gray-900 dark:text-white mt-1",
                            "{open_files}F / {open_dirs}D"
                        }
                    }
                }

                // Metadata Latency (if we have metadata ops)
                if metadata_ops > 0 {
                    div {
                        class: "px-3 py-2 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-between",
                        span {
                            class: "text-xs text-gray-500 dark:text-gray-400 pl-0.5",
                            "📋 Metadata Latency"
                        }
                        span {
                            class: "text-sm font-medium text-gray-700 dark:text-gray-200",
                            "{format_latency(metadata_latency_ms)} avg"
                        }
                    }
                }

                // Throughput Chart
                    div {
                        class: "bg-gray-100 dark:bg-gray-800 rounded-lg p-3",

                        div {
                            class: "flex items-center justify-between mb-2",

                            span {
                                class: "text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide pl-0.5",
                                "Throughput (last 60s)"
                            }

                        // Legend
                        div {
                            class: "flex items-center gap-4 text-xs",

                            div {
                                class: "flex items-center",
                                span {
                                    style: "width: 10px; height: 10px; border-radius: 50%; background-color: #60a5fa; display: inline-block; margin-right: 6px;",
                                }
                                span { class: "text-gray-500 dark:text-gray-400", "Read" }
                            }

                            div {
                                class: "flex items-center",
                                span {
                                    style: "width: 10px; height: 10px; border-radius: 50%; background-color: #fbbf24; display: inline-block; margin-right: 6px;",
                                }
                                span { class: "text-gray-500 dark:text-gray-400", "Write" }
                            }
                        }
                    }

                    // Chart SVG
                    div {
                        class: "w-full overflow-hidden rounded",
                        style: "aspect-ratio: 23 / 10; min-height: 160px;",
                        dangerous_inner_html: "{chart_svg}"
                    }
                }
            }

            // Right column
            div {
                class: "flex flex-col",
                style: "row-gap: 16px;",

                // Cache Stats
                CacheHitRateView {
                    hit_rate: hit_rate,
                    hits: hits,
                    misses: misses,
                }

                // Scheduler Stats (only shown for backends that support it, e.g., FUSE)
                if let Some(sched) = scheduler_stats {
                    SchedulerStatsView { stats: sched.clone() }
                }
            }
        }
    }
}

/// Scheduler statistics view showing I/O scheduling details
#[component]
fn SchedulerStatsView(stats: SchedulerStatsSnapshot) -> Element {
    let in_flight = stats.in_flight_total;
    let queue_total = stats.queue_depth_total;
    let queue_by_lane = stats.queue_depth_by_lane;
    let oldest_wait_ms = stats.oldest_queue_wait_ms;
    let last_dequeue_ago_ms = elapsed_since_ms(stats.last_dequeue_ms);

    let queued_value_class = if queue_total == 0 {
        "text-gray-700 dark:text-gray-200"
    } else if queue_total <= 5 {
        "text-amber-600 dark:text-amber-400"
    } else {
        "text-red-600 dark:text-red-400"
    };

    let oldest_value_class = if oldest_wait_ms == 0 {
        "text-gray-700 dark:text-gray-200"
    } else if oldest_wait_ms < 100 {
        "text-green-600 dark:text-green-400"
    } else if oldest_wait_ms < 500 {
        "text-amber-600 dark:text-amber-400"
    } else {
        "text-red-600 dark:text-red-400"
    };

    let last_dequeue_value_class = if last_dequeue_ago_ms == 0 {
        "text-gray-700 dark:text-gray-200"
    } else if last_dequeue_ago_ms < 250 {
        "text-green-600 dark:text-green-400"
    } else if last_dequeue_ago_ms < 1000 {
        "text-amber-600 dark:text-amber-400"
    } else {
        "text-red-600 dark:text-red-400"
    };

    let inflight_value_class = if in_flight == 0 {
        "text-gray-700 dark:text-gray-200"
    } else {
        "text-blue-600 dark:text-blue-400"
    };

    rsx! {
        div {
            class: "bg-gray-100 dark:bg-gray-800 rounded-lg p-3 mt-4",

            div {
                class: "flex items-center justify-between mb-3",
                span {
                    class: "text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide pl-0.5",
                    "I/O Scheduler"
                }
                span {
                    class: "text-xs text-gray-500 dark:text-gray-400",
                    "In-flight: {in_flight}"
                }
            }

            // Metrics grid
            div {
                class: "grid gap-3",
                style: "grid-template-columns: minmax(190px, 1.2fr) minmax(160px, 1fr);",

                SchedulerMetric {
                    label: "Queued",
                    value: format!("{queue_total}"),
                    detail: "Total queued".to_string(),
                    value_class: queued_value_class,
                }

                SchedulerMetric {
                    label: "Oldest Wait",
                    value: format_elapsed_ms(oldest_wait_ms),
                    detail: "Oldest queued item".to_string(),
                    value_class: oldest_value_class,
                }

                SchedulerMetric {
                    label: "Last Dequeue",
                    value: format_elapsed_ms(last_dequeue_ago_ms),
                    detail: "Since last dispatch".to_string(),
                    value_class: last_dequeue_value_class,
                }

                SchedulerMetric {
                    label: "In-Flight",
                    value: format!("{in_flight}"),
                    detail: format!("Executor queue {}", stats.executor_queue_depth),
                    value_class: inflight_value_class,
                }
            }

            // Lane queue counts
            div {
                class: "grid gap-2 mt-3",
                style: "grid-template-columns: repeat(3, minmax(0, 1fr));",

                LaneCountChip { label: "Control", value: queue_by_lane[0] }
                LaneCountChip { label: "Metadata", value: queue_by_lane[1] }
                LaneCountChip { label: "Read", value: queue_by_lane[2] }
                LaneCountChip { label: "Write", value: queue_by_lane[3] }
                LaneCountChip { label: "Bulk", value: queue_by_lane[4] }
            }

            // Lane distribution bar (always shown to avoid flashing)
            LaneDistributionBar { lanes: queue_by_lane, total: queue_total }
        }
    }
}

/// Lane distribution visualization as a stacked bar
#[component]
fn LaneDistributionBar(lanes: [u64; 5], total: u64) -> Element {
    // Lane names and colors (matching priority order)
    // L0-Control (highest), L1-Metadata, L2-ReadFg, L3-WriteFg, L4-Bulk (lowest)
    let lane_info: [(&str, &str); 5] = [
        ("Ctrl", "bg-red-500"),      // L0 - Control (rare, high priority)
        ("Meta", "bg-purple-500"),   // L1 - Metadata ops
        ("Read", "bg-blue-500"),     // L2 - Foreground reads
        ("Write", "bg-amber-500"),   // L3 - Foreground writes
        ("Bulk", "bg-gray-500"),     // L4 - Bulk/background
    ];

    // Calculate percentages (avoid division by zero)
    let total_f = if total > 0 { total as f64 } else { 1.0 };
    let empty_class = if total == 0 { "opacity-70" } else { "" };

    rsx! {
        div {
            class: "mt-3 pt-3 border-t border-gray-200 dark:border-gray-700",

            // Header
            div {
                class: "flex items-center justify-between mb-2",
                span {
                    class: "text-xs text-gray-500 dark:text-gray-400 pl-0.5",
                    "Queue Distribution"
                }
                span {
                    class: "text-xs text-gray-500 dark:text-gray-400",
                    "{total} queued"
                }
            }

            // Stacked bar
            div {
                class: "h-4 w-full rounded-full overflow-hidden flex bg-gray-200 dark:bg-gray-600 border border-gray-300/70 dark:border-gray-600/70",

                for (i, &count) in lanes.iter().enumerate() {
                    {
                        let pct = if total == 0 {
                            100.0 / 5.0
                        } else {
                            count as f64 / total_f * 100.0
                        };
                        let (_, color) = lane_info[i];
                        rsx! {
                            div {
                                class: "{color} {empty_class}",
                                style: "width: {pct}%;",
                            }
                        }
                    }
                }
            }

            // Legend (compact, always show all lanes)
            div {
                class: "flex flex-wrap gap-x-3 gap-y-1 mt-2 text-xs pl-0.5",

                for (i, &count) in lanes.iter().enumerate() {
                    {
                        let (name, color) = lane_info[i];
                        rsx! {
                            div {
                                class: "flex items-center",
                                span {
                                    class: "w-2.5 h-2.5 rounded-full {color} mr-1",
                                }
                                span {
                                    class: "text-gray-600 dark:text-gray-300",
                                    "{name}: {count}"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Individual scheduler metric display
#[component]
fn SchedulerMetric(
    label: &'static str,
    value: String,
    detail: String,
    value_class: &'static str,
) -> Element {
    rsx! {
        div {
            // Use slightly lighter/darker shade than parent container for subtle depth
            class: "px-3 py-2 bg-gray-50 dark:bg-gray-700 rounded text-left",
            span {
                class: "text-xs text-gray-500 dark:text-gray-400 block pl-0.5",
                "{label}"
            }
            span {
                class: "text-base font-semibold {value_class} block",
                "{value}"
            }
            span {
                // Secondary text - darker in light mode, lighter in dark mode
                class: "text-xs text-gray-500 dark:text-gray-400",
                "{detail}"
            }
        }
    }
}

/// Small lane count pill
#[component]
fn LaneCountChip(label: &'static str, value: u64) -> Element {
    rsx! {
        div {
            class: "px-2 py-1 rounded-md bg-gray-50 dark:bg-gray-700 text-center",
            span { class: "text-[11px] text-gray-500 dark:text-gray-400 block", "{label}" }
            span { class: "text-sm font-semibold text-gray-800 dark:text-gray-200", "{value}" }
        }
    }
}

/// Format bytes per second rate as a human-readable string
fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        "0 B/s".to_string()
    } else if bytes_per_sec < 1024.0 {
        format!("{bytes_per_sec:.0} B/s")
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format latency in milliseconds
fn format_latency(latency_ms: f64) -> String {
    if latency_ms < 0.001 {
        "—".to_string() // No data yet
    } else if latency_ms < 1.0 {
        format!("{:.0}µs", latency_ms * 1000.0)
    } else if latency_ms < 1000.0 {
        format!("{latency_ms:.1}ms")
    } else {
        format!("{:.1}s", latency_ms / 1000.0)
    }
}

/// Throughput card showing rate and latency
#[component]
fn ThroughputCard(label: &'static str, rate: f64, latency_ms: f64, icon: &'static str) -> Element {
    let rate_str = format_rate(rate);
    let latency_str = format_latency(latency_ms);

    rsx! {
        div {
            class: "bg-gray-100 dark:bg-gray-800 rounded-lg p-4",

            div {
                class: "flex items-start justify-between mb-2",

                span {
                    class: "text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide pl-0.5",
                    "{icon} {label}"
                }
            }

            // Throughput rate (primary)
            p {
                class: "text-xl font-semibold text-gray-900 dark:text-white",
                "{rate_str}"
            }

            // Latency (secondary)
            p {
                class: "text-sm text-gray-500 dark:text-gray-400 mt-1",
                "{latency_str} avg"
            }
        }
    }
}

/// Activity status badge with colored indicator
#[component]
fn ActivityBadge(status: ActivityStatus) -> Element {
    let (color, pulse, text) = match status {
        ActivityStatus::Idle => ("bg-gray-400", false, "Idle"),
        ActivityStatus::Active => ("bg-green-500", false, "Active"),
        ActivityStatus::Reading => ("bg-blue-500", true, "Reading"),
        ActivityStatus::Writing => ("bg-amber-500", true, "Writing"),
    };

    let pulse_class = if pulse { "animate-pulse" } else { "" };

    rsx! {
        div {
            class: "inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-gray-100 dark:bg-gray-800",

            span {
                class: "w-2.5 h-2.5 rounded-full {color} {pulse_class}",
            }

            span {
                class: "text-sm font-medium text-gray-700 dark:text-gray-200",
                "{text}"
            }
        }
    }
}

/// Cache hit rate visualization with progress bar
#[component]
fn CacheHitRateView(hit_rate: f64, hits: u64, misses: u64) -> Element {
    let total = hits + misses;

    // Calculate percentage for the progress bar
    // hit_rate is in [0.0, 1.0], so hit_rate * 100.0 is in [0.0, 100.0]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let percentage = (hit_rate * 100.0) as u32;

    // Color based on hit rate
    let bar_color = if hit_rate >= 0.9 {
        "bg-green-500"
    } else if hit_rate >= 0.7 {
        "bg-yellow-500"
    } else if hit_rate >= 0.5 {
        "bg-orange-500"
    } else {
        "bg-red-500"
    };

    rsx! {
        div {
            class: "bg-gray-100 dark:bg-gray-800 rounded-lg p-3 mt-4",

            div {
                class: "flex items-center justify-between mb-2",

                span {
                    class: "text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide pl-0.5",
                    "Cache Hit Rate"
                }

                span {
                    class: "text-sm font-semibold text-gray-900 dark:text-white",
                    "{percentage}%"
                }
            }

            // Progress bar
            div {
                class: "h-2 bg-gray-300 dark:bg-gray-700 rounded-full overflow-hidden",

                div {
                    class: "h-full {bar_color} transition-all duration-300",
                    style: "width: {percentage}%",
                }
            }

            div {
                class: "flex justify-between mt-1.5 text-xs text-gray-500 dark:text-gray-400",

                span { "{hits} hits" }
                span { "{misses} misses" }
                if total > 0 {
                    span { "{total} total" }
                }
            }
        }
    }
}

/// Format duration in a human-readable way
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let mins = secs / 60;
    let hours = mins / 60;

    if hours > 0 {
        format!("{}h {}m", hours, mins % 60)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs % 60)
    } else {
        format!("{secs}s")
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn elapsed_since_ms(timestamp_ms: u64) -> u64 {
    if timestamp_ms == 0 {
        0
    } else {
        now_epoch_ms().saturating_sub(timestamp_ms)
    }
}

fn format_elapsed_ms(ms: u64) -> String {
    if ms == 0 {
        "—".to_string()
    } else if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let total_secs = ms / 1000;
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{mins}m {secs}s")
    }
}

/// Operation counter card (reads, writes, metadata)
#[component]
fn OperationCounter(label: &'static str, count: u64, icon: &'static str) -> Element {
    rsx! {
        div {
            class: "bg-gray-100 dark:bg-gray-800 rounded-lg p-2 text-center",
            span {
                class: "text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide pl-0.5",
                "{icon} {label}"
            }
            p {
                class: "text-sm font-semibold text-gray-900 dark:text-white mt-1",
                "{count}"
            }
        }
    }
}

/// Error badge showing error count with warning styling
#[component]
fn ErrorBadge(count: u64) -> Element {
    let label = if count == 1 { "error" } else { "errors" };
    rsx! {
        div {
            class: "inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-red-100 dark:bg-red-900/30",
            span {
                class: "text-xs font-medium text-red-700 dark:text-red-400",
                "⚠️ {count} {label}"
            }
        }
    }
}
