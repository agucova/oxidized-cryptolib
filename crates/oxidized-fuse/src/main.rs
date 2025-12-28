//! oxmount - Mount Cryptomator vaults as FUSE filesystems.
//!
//! Usage: oxmount --vault <path> --mount <mountpoint>
//!
//! ## Debugging with tokio-console
//!
//! Build with the `tokio-console` feature for async task introspection:
//! ```bash
//! cargo build -p oxidized-fuse --features tokio-console
//! ```
//!
//! Then run `tokio-console` in another terminal to connect (default: 127.0.0.1:6669).

use anyhow::{Context, Result};
use clap::Parser;
use oxidized_fuse::CryptomatorFS;
use std::path::PathBuf;
use std::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "oxmount")]
#[command(about = "Mount Cryptomator vaults as FUSE filesystems")]
#[command(version)]
struct Cli {
    /// Path to the Cryptomator vault
    vault: PathBuf,

    /// Mountpoint for the filesystem
    mount: PathBuf,

    /// Vault password (if not provided, will prompt or use VAULT_PASSWORD env var)
    #[arg(short, long)]
    password: Option<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Mount as read-only (default: read-write)
    #[arg(long)]
    read_only: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.debug {
        "debug"
    } else {
        "info"
    };

    #[cfg(feature = "tokio-console")]
    {
        // With tokio-console: layer console subscriber with fmt output
        // Must be initialized BEFORE CryptomatorFS creates its runtime
        let console_layer = console_subscriber::spawn();
        tracing_subscriber::registry()
            .with(console_layer)
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)))
            .init();
        info!("tokio-console enabled, connect with: tokio-console");
    }

    #[cfg(not(feature = "tokio-console"))]
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)))
        .init();

    // Validate paths
    if !cli.vault.exists() {
        anyhow::bail!("Vault path does not exist: {}", cli.vault.display());
    }
    if !cli.mount.exists() {
        anyhow::bail!("Mountpoint does not exist: {}", cli.mount.display());
    }

    // Get password (automatically zeroized when dropped)
    // Priority: CLI argument > environment variable > interactive prompt
    let password = if let Some(pwd) = cli.password {
        Zeroizing::new(pwd)
    } else if let Ok(pwd) = std::env::var("VAULT_PASSWORD") {
        Zeroizing::new(pwd)
    } else {
        Zeroizing::new(
            rpassword::prompt_password("Vault password: ")
                .context("Failed to read password")?,
        )
    };

    info!(vault = %cli.vault.display(), mount = %cli.mount.display(), "Mounting vault");

    // Create filesystem
    let fs = CryptomatorFS::new(&cli.vault, &password)
        .context("Failed to initialize filesystem")?;

    // Mount options
    // Always use AutoUnmount as kernel-level fallback for unexpected termination
    let mut options = vec![
        fuser::MountOption::FSName("cryptomator".to_string()),
        fuser::MountOption::Subtype("oxidized".to_string()),
        fuser::MountOption::AutoUnmount,
    ];

    if cli.read_only {
        options.push(fuser::MountOption::RO);
    } else {
        options.push(fuser::MountOption::RW);
    }

    // Set up channel for signal handling
    let (tx, rx) = mpsc::channel::<()>();

    // Install Ctrl+C handler for graceful unmount
    ctrlc::set_handler(move || {
        // Send signal to main thread to trigger unmount
        let _ = tx.send(());
    })
    .context("Failed to set signal handler")?;

    // Mount the filesystem in background thread
    info!("Mounting filesystem (press Ctrl+C to unmount)");

    let session = fuser::spawn_mount2(fs, &cli.mount, &options).map_err(|e| {
        error!(error = %e, "Mount failed");
        anyhow::anyhow!("Failed to mount filesystem: {}", e)
    })?;

    info!("Filesystem mounted at {}", cli.mount.display());

    // Wait for Ctrl+C or external unmount signal
    match rx.recv() {
        Ok(()) => {
            info!("Received interrupt signal, unmounting...");
        }
        Err(_) => {
            // Channel closed unexpectedly - shouldn't happen in normal operation
            warn!("Signal channel closed unexpectedly");
        }
    }

    // Explicitly drop session to trigger unmount
    // (BackgroundSession::drop calls unmount)
    drop(session);

    info!("Filesystem unmounted");
    Ok(())
}
