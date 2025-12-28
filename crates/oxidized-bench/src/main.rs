//! oxbench - Cross-implementation filesystem benchmark harness.

use anyhow::{Context, Result};
use clap::Parser;
#[allow(unused_imports)]
use oxidized_bench::{
    bench::{create_suite, BenchmarkRunner},
    cli::Cli,
    config::{BenchmarkConfig, Implementation},
    results::generate_report,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Set up logging
    let filter = if cli.verbose {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(filter)
        .init();

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

    // Run benchmarks
    let results = runner.run(&benchmarks).context("Benchmark execution failed")?;

    // Generate report
    let mut stdout = std::io::stdout();
    generate_report(&mut stdout, &results, &config)?;

    Ok(())
}

/// Print the banner with configuration summary.
fn print_banner(config: &BenchmarkConfig) {
    if config.color {
        println!();
        println!("\x1b[1;36m╔════════════════════════════════════════════════════════════╗\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m            \x1b[1;37moxbench - Filesystem Benchmark\x1b[0m               \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m╚════════════════════════════════════════════════════════════╝\x1b[0m");
        println!();
    } else {
        println!();
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║            oxbench - Filesystem Benchmark                  ║");
        println!("╚════════════════════════════════════════════════════════════╝");
        println!();
    }

    println!("Vault: {}", config.vault_path.display());
    println!("Suite: {}", config.suite);
    println!("Iterations: {}", config.effective_iterations());
    println!(
        "Implementations: {}",
        config
            .implementations
            .iter()
            .map(|i| i.name())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();
}

/// Validate the environment before running benchmarks.
fn validate_environment(config: &BenchmarkConfig) -> Result<()> {
    use oxidized_bench::config::Implementation;

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
            if !oxidized_bench::platform::fskit_available() {
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
