#![forbid(unsafe_code)]

mod auth;
mod commands;
mod output;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use oxidized_cryptolib::vault::config::{extract_master_key, validate_vault_claims};
use oxidized_cryptolib::vault::operations::VaultOperations;

use crate::auth::prompt_passphrase;
use crate::commands::{cat, cp, info, init, ls, mkdir, mv, rm, touch, tree, write};

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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with_writer(std::io::stderr)
        .init();

    // Handle init command separately (doesn't require existing vault)
    if let Commands::Init(args) = cli.command {
        return init::execute(args);
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
        Commands::Init(_) => unreachable!(), // Handled above
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
