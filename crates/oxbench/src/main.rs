//! oxbench - Cross-implementation filesystem benchmark harness.

use anyhow::{Context, Result};
use clap::Parser;
#[allow(unused_imports)]
use oxbench::{
    bench::{create_suite, BenchmarkRunner},
    cli::Cli,
    config::{BenchmarkConfig, Implementation},
    results::export_json,
};
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Set up logging with indicatif integration
    // This ensures log messages appear above progress bars without clobbering them
    let filter = if cli.verbose {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("warn")
    };

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

    // Create benchmark suite
    let benchmarks = create_suite(&config);
    tracing::info!("Created {} benchmarks", benchmarks.len());

    // Create runner
    let runner = BenchmarkRunner::new(config.clone());

    // Run benchmarks (results are printed during execution in hyperfine style)
    let results = runner.run(&benchmarks).context("Benchmark execution failed")?;

    // Print flamegraph summary if profiling was enabled
    if config.flamegraph_enabled {
        print_flamegraph_summary(&results, &config);
    }

    // Export JSON if requested
    if let Some(path) = json_output {
        export_json(&results, &config, &path).context("Failed to export JSON")?;
        println!("Results exported to: {}", path.display());
    }

    Ok(())
}

/// Print summary of generated flamegraphs.
fn print_flamegraph_summary(
    results: &[oxbench::bench::BenchmarkResult],
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

    println!("Per-benchmark flamegraphs ({} total):", flamegraph_count);
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
        if aggregate_path.exists() {
            if let Some(filename) = aggregate_path.file_name() {
                println!("  - {}", filename.to_string_lossy());
            }
        }
    }
    println!();
}

/// Print a compact one-line banner with configuration summary.
fn print_banner(config: &BenchmarkConfig) {
    use owo_colors::OwoColorize;

    let vault_name = config
        .vault_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| config.vault_path.display().to_string());

    let impls = config
        .implementations
        .iter()
        .map(|i| i.short_name())
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
    use oxbench::config::Implementation;

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
            if !oxbench::platform::fskit_available() {
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

    // Check external Cryptomator mount
    if config.implementations.contains(&Implementation::OfficialCryptomator) {
        if let Some(ref path) = config.cryptomator_path {
            if !path.exists() {
                anyhow::bail!(
                    "Cryptomator mount path does not exist: {}",
                    path.display()
                );
            }
            // Check it's a mount point by trying to read
            if std::fs::read_dir(path).is_err() {
                anyhow::bail!(
                    "Cannot read Cryptomator mount: {}. Is the vault unlocked?",
                    path.display()
                );
            }
        } else {
            anyhow::bail!(
                "Cryptomator implementation selected but no mount path provided. Use --cryptomator <PATH>"
            );
        }
    }

    Ok(())
}
