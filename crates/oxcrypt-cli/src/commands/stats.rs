//! Stats command for displaying mount statistics.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use tracing::instrument;

use crate::ipc;
use crate::state::MountStateManager;
use oxcrypt_mount::stats::{format_bytes, VaultStatsSnapshot};

#[derive(Args, Clone)]
pub struct StatsArgs {
    /// Mountpoint to show stats for (shows all if not specified)
    pub mountpoint: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// Watch mode - continuously update stats
    #[arg(short, long)]
    pub watch: bool,

    /// Refresh interval in seconds for watch mode
    #[arg(short, long, default_value = "1")]
    pub interval: u64,
}

#[derive(Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
}

#[instrument(level = "info", name = "cmd::stats", skip_all)]
pub fn run(args: &StatsArgs) -> Result<()> {
    let state_manager = MountStateManager::new()?;

    if args.watch {
        run_watch_mode(&state_manager, args)
    } else {
        run_once(&state_manager, args)
    }
}

fn run_once(state_manager: &MountStateManager, args: &StatsArgs) -> Result<()> {
    let state = state_manager.load()?;

    // Filter to specific mountpoint if provided
    let mounts: Vec<_> = if let Some(mp) = &args.mountpoint {
        state.mounts.into_iter()
            .filter(|m| &m.mountpoint == mp)
            .collect()
    } else {
        state.mounts
    };

    if mounts.is_empty() {
        if args.mountpoint.is_some() {
            anyhow::bail!("No mount found at specified mountpoint");
        } else {
            println!("No active mounts");
            return Ok(());
        }
    }

    let mut results: Vec<(String, PathBuf, String, Option<VaultStatsSnapshot>)> = Vec::new();

    for mount in mounts {
        let stats = if let Some(socket_path) = &mount.socket_path {
            match ipc::get_stats(socket_path) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::debug!("Failed to get stats for {}: {}", mount.mountpoint.display(), e);
                    None
                }
            }
        } else {
            None
        };

        results.push((
            mount.vault_path.file_name().map_or_else(|| "vault".to_string(), |n| n.to_string_lossy().to_string()),
            mount.mountpoint,
            mount.backend,
            stats,
        ));
    }

    match args.format {
        OutputFormat::Json => {
            let json_results: Vec<_> = results.iter()
                .map(|(name, mp, backend, stats)| {
                    serde_json::json!({
                        "name": name,
                        "mountpoint": mp,
                        "backend": backend,
                        "stats": stats,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_results)?);
        }
        OutputFormat::Table => {
            for (name, mountpoint, backend, stats) in results {
                println!("Vault: {} @ {} [{}]", name, mountpoint.display(), backend.to_uppercase());

                if let Some(s) = stats {
                    print_stats_table(&s);
                } else {
                    println!("  Stats unavailable (mount may not support IPC)");
                }
                println!();
            }
        }
    }

    Ok(())
}

fn run_watch_mode(state_manager: &MountStateManager, args: &StatsArgs) -> Result<()> {
    use std::time::Duration;

    println!("Watching stats (Ctrl+C to stop)...\n");

    loop {
        // Clear screen (simple approach)
        print!("\x1B[2J\x1B[1;1H");

        run_once(state_manager, args)?;

        std::thread::sleep(Duration::from_secs(args.interval));
    }
}

fn print_stats_table(stats: &VaultStatsSnapshot) {
    use comfy_table::{Table, presets::UTF8_FULL_CONDENSED};

    // Session info
    let session_duration = stats.session_start.elapsed().unwrap_or_default();
    let hours = session_duration.as_secs() / 3600;
    let mins = (session_duration.as_secs() % 3600) / 60;
    println!("  Session: {hours}h {mins}m");
    println!();

    // Throughput table
    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec!["Metric", "Read", "Write"]);
    table.add_row(vec![
        "Operations".to_string(),
        stats.total_reads.to_string(),
        stats.total_writes.to_string(),
    ]);
    table.add_row(vec![
        "Bytes".to_string(),
        format_bytes(stats.bytes_read),
        format_bytes(stats.bytes_written),
    ]);
    table.add_row(vec![
        "Avg Latency".to_string(),
        format!("{:.2} ms", stats.read_latency_avg_ms),
        format!("{:.2} ms", stats.write_latency_avg_ms),
    ]);
    println!("{table}");
    println!();

    // Metadata & errors
    println!("  Metadata Ops: {} (avg {:.2} ms)",
        stats.total_metadata_ops,
        stats.metadata_latency_avg_ms);
    println!("  Open: {} files, {} dirs", stats.open_files, stats.open_dirs);
    println!("  Errors: {}", stats.total_errors);

    // Cache stats
    println!("  Cache: {:.1}% hit rate ({} hits / {} misses)",
        stats.cache.hit_rate() * 100.0,
        stats.cache.hits,
        stats.cache.misses);
}
