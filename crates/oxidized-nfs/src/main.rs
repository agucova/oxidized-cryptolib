//! NFS mount command for Cryptomator vaults.
//!
//! This binary provides a standalone NFS mount command similar to `oxmount` for FUSE.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

/// NFS mount for Cryptomator vaults
#[derive(Parser, Debug)]
#[command(name = "oxnfs", version, about)]
struct Args {
    /// Path to the Cryptomator vault
    #[arg(short, long)]
    vault: PathBuf,

    /// Mountpoint directory
    #[arg(short, long)]
    mountpoint: PathBuf,

    /// Port to run NFS server on (default: auto-select)
    #[arg(short, long)]
    port: Option<u16>,

    /// Password (will prompt if not provided)
    #[arg(short = 'P', long, env = "VAULT_PASSWORD")]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Get password
    let _password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Vault password: ")?,
    };

    tracing::info!(vault = ?args.vault, mountpoint = ?args.mountpoint, "Starting NFS mount");

    // TODO: Implement mount logic using NfsBackend
    tracing::warn!("NFS backend not yet fully implemented");

    Ok(())
}
