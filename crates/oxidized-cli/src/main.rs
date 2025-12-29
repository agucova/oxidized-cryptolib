#![forbid(unsafe_code)]

mod auth;
mod commands;
mod ipc;
mod output;
mod state;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
#[cfg(feature = "tokio-console")]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use oxidized_cryptolib::vault::config::{extract_master_key, validate_vault_claims};
use oxidized_cryptolib::vault::operations::VaultOperations;
use oxidized_mount_common::{
    cleanup_stale_mounts, CleanupAction, CleanupOptions, TrackedMountInfo,
};

use crate::auth::prompt_passphrase;
use crate::commands::{cat, cp, info, init, ls, mkdir, mounts, mv, rm, stats, touch, tree, write};
use crate::state::MountStateManager;

#[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
use crate::commands::{backends, mount, unmount};

#[derive(Parser)]
#[command(name = "oxcrypt")]
#[command(author, version, about = "Command-line interface for Cryptomator vaults")]
#[command(propagate_version = true)]
struct Cli {
    /// Path to the Cryptomator vault (not required for init)
    #[arg(long, env = "OXCRYPT_VAULT", global = true)]
    vault: Option<PathBuf>,

    /// Vault passphrase (insecure, prefer interactive prompt or OXCRYPT_PASSWORD env var)
    #[arg(long, env = "OXCRYPT_PASSWORD", hide_env_values = true, global = true)]
    password: Option<String>,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault
    Init(init::Args),

    /// List directory contents
    Ls(ls::Args),

    /// Read and output file contents
    Cat(cat::Args),

    /// Show directory tree
    Tree(tree::Args),

    /// Create a directory
    Mkdir(mkdir::Args),

    /// Create an empty file
    Touch(touch::Args),

    /// Write stdin to a file
    Write(write::Args),

    /// Remove a file or directory
    Rm(rm::Args),

    /// Copy a file within the vault
    Cp(cp::Args),

    /// Move or rename a file or directory
    Mv(mv::Args),

    /// Show vault information
    Info(info::Args),

    /// List active mounts
    Mounts(mounts::Args),

    /// Show statistics for mounted vaults
    Stats(stats::StatsArgs),

    #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
    /// Mount the vault as a filesystem
    Mount(mount::Args),

    #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
    /// Unmount a mounted vault
    Unmount(unmount::Args),

    #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
    /// List available mount backends
    Backends(backends::Args),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up tracing based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    #[cfg(feature = "tokio-console")]
    {
        // console_subscriber returns a layer with its own built-in filter for tokio
        // instrumentation. We use per-layer filtering so the fmt layer gets our
        // custom filter while console uses its own.
        use tracing_subscriber::Layer;
        use std::net::SocketAddr;

        // CLI uses port 6669 by default (GUI uses 6670)
        let console_port: u16 = std::env::var("TOKIO_CONSOLE_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6669);

        let console_addr: SocketAddr = ([127, 0, 0, 1], console_port).into();
        let port_available = std::net::TcpListener::bind(console_addr).is_ok();

        let fmt_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into());

        if port_available {
            let console_layer = console_subscriber::ConsoleLayer::builder()
                .server_addr(console_addr)
                .spawn();
            tracing_subscriber::registry()
                .with(console_layer)
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(fmt_filter))
                .init();
            tracing::info!("tokio-console enabled, connect with: tokio-console http://127.0.0.1:{}", console_port);
        } else {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(fmt_filter))
                .init();
            tracing::warn!(
                "tokio-console port {} already in use, running without console instrumentation. \
                 Set TOKIO_CONSOLE_PORT to use a different port.",
                console_port
            );
        }
    }

    #[cfg(not(feature = "tokio-console"))]
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with_writer(std::io::stderr)
        .init();

    // Proactive cleanup of stale mounts (non-fatal)
    // Skip if OXCRYPT_NO_STARTUP_CLEANUP=1 (used by tests)
    let skip_cleanup = std::env::var("OXCRYPT_NO_STARTUP_CLEANUP")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if !skip_cleanup {
        if let Err(e) = proactive_cleanup() {
            tracing::warn!("Stale mount cleanup failed: {}", e);
        }
    }

    // Handle commands that don't require an unlocked vault
    match &cli.command {
        Commands::Init(args) => return init::execute(args.clone()),
        Commands::Mounts(args) => return mounts::execute(args.clone()),
        Commands::Stats(args) => return stats::run(args.clone()),
        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
        Commands::Mount(args) => return mount::execute(args.clone(), cli.vault.clone()),
        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
        Commands::Unmount(args) => return unmount::execute(args.clone()),
        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
        Commands::Backends(args) => return backends::execute(args.clone()),
        _ => {}
    }

    // All other commands require a vault path
    let vault_path = cli
        .vault
        .ok_or_else(|| anyhow::anyhow!("--vault is required (or set OXCRYPT_VAULT)"))?;

    // Validate vault path
    if !vault_path.exists() {
        anyhow::bail!("Vault path does not exist: {}", vault_path.display());
    }
    if !vault_path.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", vault_path.display());
    }

    // Get passphrase from flag, env var, or interactive prompt
    let passphrase = match cli.password {
        Some(p) => p,
        None => prompt_passphrase()?,
    };

    // Extract master key
    let master_key = extract_master_key(&vault_path, &passphrase)
        .context("Failed to extract master key - check your passphrase")?;

    // Validate vault configuration
    let vault_config_path = vault_path.join("vault.cryptomator");
    let vault_config = fs::read_to_string(&vault_config_path)
        .with_context(|| format!("Failed to read vault config: {}", vault_config_path.display()))?;
    let claims = validate_vault_claims(&vault_config, &master_key)
        .context("Failed to validate vault configuration")?;

    // Get cipher combo from vault configuration
    let cipher_combo = claims.cipher_combo()
        .ok_or_else(|| anyhow::anyhow!("Unsupported cipher combo: {}", claims.cipher_combo_str()))?;

    // Create vault operations handle
    let vault_ops = VaultOperations::with_options(
        &vault_path,
        master_key,
        claims.shortening_threshold(),
        cipher_combo,
    );

    // Execute command
    match cli.command {
        // These are handled above (before vault unlock)
        Commands::Init(_) | Commands::Mounts(_) | Commands::Stats(_) => unreachable!(),
        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
        Commands::Mount(_) | Commands::Unmount(_) | Commands::Backends(_) => unreachable!(),
        Commands::Ls(args) => ls::execute(&vault_ops, args),
        Commands::Cat(args) => cat::execute(&vault_ops, args),
        Commands::Tree(args) => tree::execute(&vault_ops, args),
        Commands::Mkdir(args) => mkdir::execute(&vault_ops, args),
        Commands::Touch(args) => touch::execute(&vault_ops, args),
        Commands::Write(args) => write::execute(&vault_ops, args),
        Commands::Rm(args) => rm::execute(&vault_ops, args),
        Commands::Cp(args) => cp::execute(&vault_ops, args),
        Commands::Mv(args) => mv::execute(&vault_ops, args),
        Commands::Info(args) => info::execute(&vault_path, &claims, args),
    }
}

/// Proactively clean up stale mounts from previous sessions.
///
/// This runs at CLI startup to detect and clean up mounts that were left behind
/// from crashed processes or killed daemons. It's non-fatal - errors are logged
/// but don't prevent CLI operation.
///
/// # Safety
///
/// This function NEVER unmounts:
/// - Active mounts (process still alive)
/// - Foreign mounts (not created by oxidized-cryptolib)
/// - Orphaned mounts (ours but not tracked) - only warns about these
fn proactive_cleanup() -> Result<()> {
    let state_manager = MountStateManager::new()?;
    let state = state_manager.load()?;

    if state.mounts.is_empty() {
        return Ok(());
    }

    // Convert state entries to TrackedMountInfo for cleanup
    let tracked_mounts: Vec<TrackedMountInfo> = state
        .mounts
        .iter()
        .map(|e| TrackedMountInfo {
            mountpoint: e.mountpoint.clone(),
            pid: e.pid,
        })
        .collect();

    let options = CleanupOptions::default();
    let results = cleanup_stale_mounts(&tracked_mounts, &options)?;

    let mut removed_mountpoints = Vec::new();

    for result in &results {
        match &result.action {
            CleanupAction::Unmounted if result.success => {
                tracing::info!("Cleaned stale mount: {}", result.mountpoint.display());
                removed_mountpoints.push(result.mountpoint.clone());
            }
            CleanupAction::Unmounted => {
                tracing::warn!(
                    "Failed to clean stale mount {}: {}",
                    result.mountpoint.display(),
                    result.error.as_deref().unwrap_or("unknown error")
                );
                // Still remove from state - the mount is likely already gone
                removed_mountpoints.push(result.mountpoint.clone());
            }
            CleanupAction::RemovedFromState => {
                tracing::debug!(
                    "Removed stale state entry for {}",
                    result.mountpoint.display()
                );
                removed_mountpoints.push(result.mountpoint.clone());
            }
            CleanupAction::Warning => {
                // Orphaned mount - warn but don't remove
                eprintln!(
                    "Warning: orphaned mount at {} (use 'diskutil unmount force {}' to remove)",
                    result.mountpoint.display(),
                    result.mountpoint.display()
                );
            }
            CleanupAction::Skipped { reason } => {
                tracing::debug!(
                    "Skipped {}: {}",
                    result.mountpoint.display(),
                    reason
                );
            }
        }
    }

    // Remove cleaned mounts from state (thread-safe)
    for mountpoint in removed_mountpoints {
        if let Err(e) = state_manager.remove_by_mountpoint(&mountpoint) {
            tracing::warn!(
                "Failed to remove {} from state: {}",
                mountpoint.display(),
                e
            );
        }
    }

    Ok(())
}
