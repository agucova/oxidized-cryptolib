//! oxmount - Mount Cryptomator vaults as FUSE filesystems.
//!
//! Usage: oxmount --vault <path> --mount <mountpoint>

use anyhow::{Context, Result};
use clap::Parser;
use oxidized_fuse::CryptomatorFS;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "oxmount")]
#[command(about = "Mount Cryptomator vaults as FUSE filesystems")]
#[command(version)]
struct Cli {
    /// Path to the Cryptomator vault
    #[arg(short, long)]
    vault: PathBuf,

    /// Mountpoint for the filesystem
    #[arg(short, long)]
    mount: PathBuf,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.debug {
        "debug"
    } else {
        "info"
    };

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

    // Get password
    let password = rpassword::prompt_password("Vault password: ")
        .context("Failed to read password")?;

    info!(vault = %cli.vault.display(), mount = %cli.mount.display(), "Mounting vault");

    // Create filesystem
    let fs = CryptomatorFS::new(&cli.vault, &password)
        .context("Failed to initialize filesystem")?;

    // Mount options
    let mut options = vec![
        fuser::MountOption::RO,  // Start with read-only for safety during testing
        fuser::MountOption::FSName("cryptomator".to_string()),
        fuser::MountOption::Subtype("oxidized".to_string()),
    ];

    if !cli.foreground {
        options.push(fuser::MountOption::AutoUnmount);
    }

    // Mount the filesystem
    info!("Mounting filesystem (press Ctrl+C to unmount)");

    if let Err(e) = fuser::mount2(fs, &cli.mount, &options) {
        error!(error = %e, "Mount failed");
        anyhow::bail!("Failed to mount filesystem: {}", e);
    }

    info!("Filesystem unmounted");
    Ok(())
}
