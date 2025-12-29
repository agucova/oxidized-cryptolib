//! FSKit mount tool for Cryptomator vaults on macOS 15.4+.
//!
//! This binary mounts a Cryptomator vault using Apple's FSKit framework,
//! providing native filesystem access without kernel extensions.
//!
//! ## Debugging with tokio-console
//!
//! Build with the `tokio-console` feature for async task introspection:
//! ```bash
//! cargo build -p oxidized-fskit --features tokio-console
//! ```
//!
//! Then run `tokio-console` in another terminal to connect (default: 127.0.0.1:6669).

use anyhow::Result;
use clap::Parser;
use fskit_rs::{mount, MountOptions};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use oxidized_fskit::CryptomatorFSKit;

/// Mount a Cryptomator vault using FSKit (macOS 15.4+).
#[derive(Parser, Debug)]
#[command(name = "oxmount-fskit")]
#[command(version, about = "Mount Cryptomator vaults using FSKit")]
struct Args {
    /// Path to the Cryptomator vault directory
    vault: PathBuf,

    /// Mount point (default: /tmp/cryptomator)
    #[arg(short, long, default_value = "/tmp/cryptomator")]
    mount_point: PathBuf,

    /// Vault password (prompts if not provided)
    #[arg(short, long, env = "VAULT_PASSWORD")]
    password: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Force unmount if mount point is already in use
    #[arg(short, long, default_value = "true")]
    force: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    #[cfg(feature = "tokio-console")]
    {
        // console_subscriber::spawn() returns a layer with its own built-in filter
        // for tokio instrumentation. We use per-layer filtering so the fmt layer
        // gets our custom filter while console uses its own.
        use tracing_subscriber::Layer;
        let console_layer = console_subscriber::spawn();
        tracing_subscriber::registry()
            .with(console_layer)
            .with(tracing_subscriber::fmt::layer().with_filter(filter))
            .init();
        info!("tokio-console enabled, connect with: tokio-console http://127.0.0.1:6669");
    }

    #[cfg(not(feature = "tokio-console"))]
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Get password
    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Vault password: ")?,
    };

    // Validate vault path
    if !args.vault.exists() {
        anyhow::bail!("Vault path does not exist: {}", args.vault.display());
    }

    let vault_config = args.vault.join("vault.cryptomator");
    if !vault_config.exists() {
        anyhow::bail!(
            "Not a valid Cryptomator vault (missing vault.cryptomator): {}",
            args.vault.display()
        );
    }

    // Create mount point if it doesn't exist
    if !args.mount_point.exists() {
        std::fs::create_dir_all(&args.mount_point)?;
    }

    // Initialize filesystem
    info!("Opening vault: {}", args.vault.display());
    let fs = CryptomatorFSKit::new(&args.vault, &password)?;

    // Configure mount options
    let opts = MountOptions {
        mount_point: args.mount_point.clone(),
        force: args.force,
        ..Default::default()
    };

    info!("Mounting at {}...", args.mount_point.display());

    // Mount the filesystem
    let session = mount(fs, opts).await?;

    println!(
        "Vault mounted at {}",
        args.mount_point.display()
    );
    println!("Press Ctrl+C to unmount.");

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    println!("\nUnmounting...");
    drop(session);

    info!("Unmounted successfully");
    Ok(())
}
