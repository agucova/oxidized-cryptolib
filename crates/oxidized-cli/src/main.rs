#![forbid(unsafe_code)]

mod auth;
mod commands;
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

use crate::auth::prompt_passphrase;
use crate::commands::{cat, cp, info, init, ls, mkdir, mounts, mv, rm, touch, tree, write};

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

    // Handle commands that don't require an unlocked vault
    match &cli.command {
        Commands::Init(args) => return init::execute(args.clone()),
        Commands::Mounts(args) => return mounts::execute(args.clone()),
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
        Commands::Init(_) | Commands::Mounts(_) => unreachable!(),
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
