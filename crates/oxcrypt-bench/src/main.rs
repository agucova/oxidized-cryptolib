//! oxbench - Cross-implementation filesystem benchmark harness.

// Use mimalloc for reduced allocation latency (enabled by default).
// Disable with `--no-default-features` if debugging allocator issues.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::Parser;
#[allow(unused_imports)]
use oxcrypt_bench::{
    bench::{create_suite, BenchmarkRunner},
    cli::Cli,
    config::{BenchmarkConfig, Implementation},
    results::export_json,
};
use oxcrypt_mount::{cleanup_stale_mounts, signal, CleanupAction, CleanupOptions, TrackedMountInfo};
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() -> Result<()> {
    // Install a custom panic hook that avoids backtrace printing.
    // This works around a bug in nightly Rust where backtrace Display::fmt
    // can recurse infinitely, causing a stack overflow during panic handling.
    // See: https://github.com/rust-lang/rust/issues/52785
    std::panic::set_hook(Box::new(|info| {
        use std::io::Write;
        let mut stderr = std::io::stderr().lock();

        // Write directly to stderr, bypassing buffering
        let _ = writeln!(stderr, "\n=== PANIC CAPTURED ===");
        let _ = writeln!(stderr, "Thread: {:?}", std::thread::current().name());
        let _ = writeln!(stderr, "Location: {:?}", info.location());

        // Extract panic message
        if let Some(s) = info.payload().downcast_ref::<&str>() {
            let _ = writeln!(stderr, "Message: {s}");
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            let _ = writeln!(stderr, "Message: {s}");
        } else {
            let _ = writeln!(stderr, "Message: {info:?}");
        }

        let _ = writeln!(stderr, "======================\n");
        let _ = stderr.flush();

        // CRITICAL: Abort immediately to prevent backtrace recursion
        std::process::abort();
    }));

    // Install signal handler for clean benchmark interruption
    // This ensures any active mounts are cleaned up on Ctrl+C
    if let Err(e) = signal::install_signal_handler() {
        tracing::warn!("Failed to install signal handler: {}", e);
    }

    // Parse CLI arguments
    let cli = Cli::parse();

    // Set up logging with indicatif integration
    // This ensures log messages appear above progress bars without clobbering them
    // Respect RUST_LOG if set, otherwise use default based on verbose flag
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if cli.verbose {
                EnvFilter::new("info")
            } else {
                EnvFilter::new("warn")
            }
        });

    let indicatif_layer = IndicatifLayer::new();
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(false)
                .with_writer(indicatif_layer.get_stderr_writer()),
        )
        .with(indicatif_layer)
        .with(filter)
        .init();

    if let Err(e) = proactive_cleanup() {
        tracing::warn!("Stale mount cleanup failed: {}", e);
    }

    // Handle asset management commands (don't require vault)
    if cli.is_asset_command() {
        cli.execute_asset_command()?;
        return Ok(());
    }

    // Extract JSON output path before consuming cli
    let json_output = cli.json.clone();

    // Build configuration
    let config = cli.into_config().context("Failed to create benchmark config")?;

    // Print banner
    print_banner(&config);

    // Validate environment
    validate_environment(&config)?;

    // Clean up any leftover benchmark artifacts from previous interrupted runs
    cleanup_benchmark_artifacts(&config);

    // Create benchmark suite
    let benchmarks = create_suite(&config);
    tracing::info!("Created {} benchmarks", benchmarks.len());

    // Create runner
    let runner = BenchmarkRunner::new(config.clone());

    // Run benchmarks (results are printed during execution in hyperfine style)
    let results = match runner.run(&benchmarks) {
        Ok(r) => r,
        Err(e) => {
            // Check if this was a clean interruption (Ctrl+C or timeout)
            if signal::shutdown_requested() {
                eprintln!("\nBenchmark interrupted.");
                std::process::exit(130); // Standard exit code for SIGINT (128 + 2)
            }
            // Real error - show full details
            return Err(e).context("Benchmark execution failed");
        }
    };

    // Print flamegraph summary if profiling was enabled
    if config.flamegraph_enabled {
        print_flamegraph_summary(&results, &config);
    }

    // Export JSON if requested
    if let Some(path) = json_output {
        export_json(&results, &config, &path).context("Failed to export JSON")?;
        println!("Results exported to: {}", path.display());
    }

    // Brief delay to allow background threads (indicatif tick threads, tracing layer)
    // to terminate cleanly. Without this, the process can hang in exit state.
    std::thread::sleep(std::time::Duration::from_millis(100));

    Ok(())
}

fn proactive_cleanup() -> Result<()> {
    let tracked: Vec<TrackedMountInfo> = Vec::new();
    let options = CleanupOptions {
        // IMPORTANT: Do NOT enable cleanup_orphans in oxbench!
        // oxbench creates temporary mounts during benchmarking and cleans them up when done.
        // It doesn't track persistent daemon mounts, so an empty tracked list + cleanup_orphans
        // would force unmount ALL Cryptomator mounts (including external ones like official app).
        cleanup_orphans: false,
        warn_orphans: false, // Also disable warnings since we have no tracked mounts
        ..CleanupOptions::default()
    };

    let results = cleanup_stale_mounts(&tracked, &options)?;

    for result in results {
        match &result.action {
            CleanupAction::Unmounted if result.success => {
                tracing::info!("Cleaned stale mount: {}", result.mountpoint.display());
            }
            CleanupAction::Unmounted => {
                tracing::warn!(
                    "Failed to clean stale mount {}: {}",
                    result.mountpoint.display(),
                    result.error.as_deref().unwrap_or("unknown error")
                );
            }
            CleanupAction::Skipped { reason } => {
                tracing::debug!(
                    "Skipped {}: {}",
                    result.mountpoint.display(),
                    reason
                );
            }
            CleanupAction::RemovedFromState | CleanupAction::Warning => {}
        }
    }

    Ok(())
}

/// Print summary of generated flamegraphs.
fn print_flamegraph_summary(
    results: &[oxcrypt_bench::bench::BenchmarkResult],
    config: &BenchmarkConfig,
) {
    let flamegraph_count = results.iter().filter(|r| r.flamegraph_path.is_some()).count();

    if flamegraph_count == 0 {
        return;
    }

    println!();
    if config.color {
        println!("\x1b[1;36m{:-^80}\x1b[0m", " FLAMEGRAPHS ");
    } else {
        println!("{:-^80}", " FLAMEGRAPHS ");
    }
    println!();
    println!(
        "Flamegraphs saved to: {}",
        config.flamegraph_dir.display()
    );
    println!();

    // Group by implementation
    let mut by_impl: std::collections::HashMap<String, Vec<&std::path::Path>> =
        std::collections::HashMap::new();

    for result in results {
        if let Some(ref path) = result.flamegraph_path {
            by_impl
                .entry(result.implementation.name().to_string())
                .or_default()
                .push(path.as_path());
        }
    }

    println!("Per-benchmark flamegraphs ({flamegraph_count} total):");
    for (impl_name, paths) in &by_impl {
        println!("  {}: {} files", impl_name, paths.len());
        for path in paths.iter().take(3) {
            if let Some(filename) = path.file_name() {
                println!("    - {}", filename.to_string_lossy());
            }
        }
        if paths.len() > 3 {
            println!("    ... and {} more", paths.len() - 3);
        }
    }
    println!();

    // List aggregate flamegraphs
    println!("Aggregate per-implementation flamegraphs:");
    for impl_type in &config.implementations {
        let aggregate_path = config
            .flamegraph_dir
            .join(format!("{}_all.svg", impl_type.short_name().to_lowercase()));
        if aggregate_path.exists()
            && let Some(filename) = aggregate_path.file_name() {
                println!("  - {}", filename.to_string_lossy());
            }
    }
    println!();
}

/// Print a compact one-line banner with configuration summary.
fn print_banner(config: &BenchmarkConfig) {
    use owo_colors::OwoColorize;

    let vault_name = config
        .vault_path
        .file_name().map_or_else(|| config.vault_path.display().to_string(), |n| n.to_string_lossy().to_string());

    let impls = config
        .implementations
        .iter()
        .map(Implementation::short_name)
        .collect::<Vec<_>>()
        .join(", ");

    println!();
    if config.color {
        println!(
            "{}: {} ({}) - {} iterations",
            "oxbench".cyan().bold(),
            vault_name,
            impls,
            config.effective_iterations()
        );
    } else {
        println!(
            "oxbench: {} ({}) - {} iterations",
            vault_name,
            impls,
            config.effective_iterations()
        );
    }
    println!();
}

/// Validate the environment before running benchmarks.
fn validate_environment(config: &BenchmarkConfig) -> Result<()> {
    // Check vault exists
    if !config.vault_path.exists() {
        anyhow::bail!("Vault path does not exist: {}", config.vault_path.display());
    }

    // Check vault.cryptomator file exists
    let vault_config = config.vault_path.join("vault.cryptomator");
    if !vault_config.exists() {
        anyhow::bail!(
            "Not a valid Cryptomator vault (missing vault.cryptomator): {}",
            config.vault_path.display()
        );
    }

    // Check FSKit availability
    if config.implementations.contains(&Implementation::OxidizedFsKit) {
        #[cfg(target_os = "macos")]
        {
            if !oxcrypt_bench::platform::fskit_available() {
                anyhow::bail!(
                    "FSKit is not available on this system. Requires macOS 15.4 or later."
                );
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            anyhow::bail!("FSKit is only available on macOS");
        }
    }

    // Check external vault mount
    if config.implementations.contains(&Implementation::OfficialCryptomator) {
        if let Some(ref path) = config.external_vault_path {
            if !path.exists() {
                anyhow::bail!(
                    "External vault path does not exist: {}",
                    path.display()
                );
            }
            // Check it's a mount point by trying to read
            if std::fs::read_dir(path).is_err() {
                anyhow::bail!(
                    "Cannot read external vault: {}. Is it mounted?",
                    path.display()
                );
            }
        } else {
            anyhow::bail!(
                "External implementation selected but no mount path provided. Use --external-vault <PATH>"
            );
        }
    }

    Ok(())
}

/// Clean up leftover benchmark artifacts from previous interrupted runs.
///
/// Removes any `bench_*` directories from the external vault mount path
/// to ensure a clean slate before benchmarks start.
fn cleanup_benchmark_artifacts(config: &BenchmarkConfig) {
    // Only clean up the external vault mount if specified
    // (other backends create temporary mounts that don't persist)
    if let Some(ref mount_path) = config.external_vault_path
        && mount_path.exists() {
            tracing::debug!("Cleaning up benchmark artifacts from {}", mount_path.display());

            match std::fs::read_dir(mount_path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Some(name) = path.file_name()
                            && name.to_string_lossy().starts_with("bench_") {
                                tracing::info!("Removing leftover artifact: {}", path.display());
                                if path.is_dir() {
                                    if let Err(e) = std::fs::remove_dir_all(&path) {
                                        tracing::warn!("Failed to remove {}: {}", path.display(), e);
                                    }
                                } else if let Err(e) = std::fs::remove_file(&path) {
                                    tracing::warn!("Failed to remove {}: {}", path.display(), e);
                                }
                            }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read Cryptomator mount for cleanup: {}", e);
                }
            }
        }
}
