//! Standalone Statistics Window
//!
//! This is a separate window component that runs in its own VirtualDom.
//! It displays real-time vault activity statistics.

use dioxus::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::backend::{mount_manager, ActivityStatus, VaultStats};

/// State for calculating throughput rates.
#[derive(Clone, Copy)]
struct PrevStats {
    bytes_read: u64,
    bytes_written: u64,
    timestamp: Option<Instant>,
}

impl Default for PrevStats {
    fn default() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            timestamp: None,
        }
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
    let theme_class = config.read().theme.css_class().unwrap_or("");
    let platform_class = crate::current_platform().css_class();

    // Get stats from mount manager
    let stats = mount_manager().get_stats(&vault_id);

    // State for calculating throughput rates
    let mut prev_stats = use_signal(PrevStats::default);

    // Auto-refresh stats every 500ms
    let mut refresh_counter = use_signal(|| 0u32);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
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
                    {StatsContent(stats, &mut prev_stats)}
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

/// Stats content - extracts data from Arc<VaultStats> and calculates throughput
/// Note: Not a #[component] because Arc<VaultStats> doesn't implement PartialEq
#[allow(non_snake_case)]
fn StatsContent(stats: &Arc<VaultStats>, prev_stats: &mut Signal<PrevStats>) -> Element {
    // Extract current values
    let activity = stats.activity_status(Duration::from_millis(500));
    let session_duration = stats.session_duration();
    let bytes_read = stats.bytes_read();
    let bytes_written = stats.bytes_written();

    // Get latency from stats
    let read_latency_ms = stats.avg_read_latency_ms();
    let write_latency_ms = stats.avg_write_latency_ms();

    // Cache stats
    let cache = stats.cache_stats();
    let hit_rate = cache.hit_rate();
    let hits = cache.hit_count();
    let misses = cache.miss_count();

    // Calculate throughput rates
    let prev = *prev_stats.read();
    let now = Instant::now();

    let (read_rate, write_rate) = if let Some(prev_time) = prev.timestamp {
        let elapsed = prev_time.elapsed().as_secs_f64().max(0.001); // Avoid div by zero
        let read_delta = bytes_read.saturating_sub(prev.bytes_read);
        let write_delta = bytes_written.saturating_sub(prev.bytes_written);
        (read_delta as f64 / elapsed, write_delta as f64 / elapsed)
    } else {
        (0.0, 0.0)
    };

    // Update previous stats for next calculation
    prev_stats.set(PrevStats {
        bytes_read,
        bytes_written,
        timestamp: Some(now),
    });

    rsx! {
        // Activity Status Badge
        div {
            class: "flex items-center justify-between mb-4",
            ActivityBadge { status: activity }
            span {
                class: "text-sm text-gray-600 dark:text-gray-300",
                "Session: {format_duration(session_duration)}"
            }
        }

        // Read/Write Performance Cards
        div {
            class: "grid grid-cols-2 gap-3",

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

        // Cache Stats
        CacheHitRateView {
            hit_rate: hit_rate,
            hits: hits,
            misses: misses,
        }
    }
}

/// Format bytes per second rate as a human-readable string
fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        "0 B/s".to_string()
    } else if bytes_per_sec < 1024.0 {
        format!("{:.0} B/s", bytes_per_sec)
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
        format!("{:.1}ms", latency_ms)
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
                    class: "text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide",
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
                    class: "text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide",
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
        format!("{}s", secs)
    }
}
