//! oxmount - Mount Cryptomator vaults as FUSE filesystems.
//!
//! Usage: oxmount --vault <path> --mount <mountpoint>

use anyhow::{Context, Result};
use clap::Parser;
use oxidized_fuse::CryptomatorFS;
use std::path::PathBuf;
use tracing::{error, info};
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

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

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
    let mut options = vec![
        fuser::MountOption::FSName("cryptomator".to_string()),
        fuser::MountOption::Subtype("oxidized".to_string()),
    ];

    if cli.read_only {
        options.push(fuser::MountOption::RO);
    } else {
        options.push(fuser::MountOption::RW);
    }

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
