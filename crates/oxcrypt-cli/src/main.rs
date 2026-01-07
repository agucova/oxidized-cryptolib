#![deny(unsafe_code)]

// Use mimalloc for reduced allocation latency (enabled by default).
// Disable with `--no-default-features` if debugging allocator issues.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod auth;
mod commands;
mod config;
mod exit_code;
mod ipc;
mod output;
mod state;

use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ColorChoice};
use tracing_subscriber::EnvFilter;
#[cfg(feature = "tokio-console")]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use oxcrypt_core::crypto::CryptoError;
use oxcrypt_core::vault::config::{extract_master_key, validate_vault_claims, MasterKeyExtractionError};
use oxcrypt_core::vault::operations::{VaultOperations, VaultOperationError};
use oxcrypt_mount::{
    cleanup_stale_mounts, CleanupAction, CleanupOptions, MountError, TrackedMountInfo,
};

use crate::commands::{cat, completions, cp, export, import, info, init, ls, mkdir, mounts, mv, rm, stats, touch, tree, write};
use crate::state::MountStateManager;

#[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
use crate::commands::{backends, exec, mount, unmount};

/// Command-line interface for Cryptomator vaults
#[derive(Parser)]
#[command(name = "oxcrypt")]
#[command(author, version)]
#[command(propagate_version = true)]
#[command(after_help = "EXAMPLES:
    # List vault contents
    oxcrypt ls ~/vault /

    # Read a file (pipe password from secret manager)
    echo \"$SECRET\" | oxcrypt --password-stdin cat ~/vault /secret.txt

    # Mount vault and run a command
    oxcrypt exec ~/vault -- grep -r \"password\" .

    # Mount vault as filesystem
    oxcrypt mount ~/vault /mnt/vault

    # Use vault alias (from ~/.config/oxcrypt/config.toml)
    oxcrypt ls @work /
")]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// When to use colored output
    #[arg(long, value_enum, default_value = "auto", global = true)]
    color: ColorChoice,

    /// Vault passphrase (insecure, prefer --password-stdin or OXCRYPT_PASSWORD)
    #[arg(long, env = "OXCRYPT_PASSWORD", hide_env_values = true, global = true)]
    password: Option<String>,

    /// Read password from stdin (single line)
    #[arg(long, conflicts_with = "password", global = true)]
    password_stdin: bool,

    /// Read password from file descriptor
    #[arg(long, value_name = "FD", conflicts_with_all = ["password", "password_stdin"], global = true)]
    password_fd: Option<i32>,

    #[command(subcommand)]
    command: Commands,
}

/// Password options extracted from CLI for vault operations
#[derive(Clone, Default)]
pub struct PasswordOptions {
    pub password: Option<String>,
    pub password_stdin: bool,
    pub password_fd: Option<i32>,
}

impl From<&Cli> for PasswordOptions {
    fn from(cli: &Cli) -> Self {
        Self {
            password: cli.password.clone(),
            password_stdin: cli.password_stdin,
            password_fd: cli.password_fd,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    // ============ Vault file operations (require vault path) ============

    /// List directory contents
    Ls(VaultCommand<ls::Args>),

    /// Read and output file contents
    Cat(VaultCommand<cat::Args>),

    /// Show directory tree
    Tree(VaultCommand<tree::Args>),

    /// Create a directory
    Mkdir(VaultCommand<mkdir::Args>),

    /// Create an empty file
    Touch(VaultCommand<touch::Args>),

    /// Write stdin to a file
    Write(VaultCommand<write::Args>),

    /// Remove a file or directory
    Rm(VaultCommand<rm::Args>),

    /// Copy a file within the vault
    Cp(VaultCommand<cp::Args>),

    /// Move or rename a file or directory
    Mv(VaultCommand<mv::Args>),

    /// Import files from local filesystem into vault
    Import(VaultCommand<import::Args>),

    /// Export files from vault to local filesystem
    Export(VaultCommand<export::Args>),

    /// Show vault information
    Info(VaultCommand<info::Args>),

    // ============ Standalone commands (no vault required) ============

    /// Create a new vault
    Init(init::Args),

    /// List active mounts
    Mounts(mounts::Args),

    /// Show statistics for mounted vaults
    Stats(stats::StatsArgs),

    /// Generate shell completions
    Completions(completions::Args),

    // ============ Mount commands (feature-gated) ============

    #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
    /// Mount vault as a filesystem
    Mount(mount::Args),

    #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
    /// Unmount a mounted vault
    Unmount(unmount::Args),

    #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
    /// List available mount backends
    Backends(backends::Args),

    #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
    /// Mount vault, run command, then unmount
    Exec(exec::Args),
}

/// Wrapper for commands that operate on a vault
#[derive(Parser, Clone)]
pub struct VaultCommand<T: clap::Args> {
    /// Path to the Cryptomator vault (or @alias from config)
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,

    #[command(flatten)]
    pub args: T,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(exit_code::SUCCESS),
        Err(e) => {
            // Determine appropriate exit code based on error type
            let code = categorize_error(&e);

            // Only print error if not quiet mode (quiet is parsed separately for this)
            let args: Vec<String> = std::env::args().collect();
            let is_quiet = args.iter().any(|a| a == "-q" || a == "--quiet");

            if !is_quiet {
                eprintln!("Error: {e:#}");
            }

            ExitCode::from(code)
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Set up tracing based on verbosity (skip if quiet)
    if !cli.quiet {
        setup_tracing(cli.verbose);
    }

    // Proactive cleanup of stale mounts and IPC sockets (non-fatal)
    // Skip if OXCRYPT_NO_STARTUP_CLEANUP=1 (used by tests)
    let skip_cleanup = std::env::var("OXCRYPT_NO_STARTUP_CLEANUP")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if !skip_cleanup {
        if let Err(e) = proactive_cleanup() {
            tracing::warn!("Stale mount cleanup failed: {}", e);
        }
        // Clean up stale IPC sockets from crashed processes
        ipc::cleanup_stale_sockets();
    }

    // Extract password options from global CLI for vault commands
    let password_opts = PasswordOptions::from(&cli);

    // Execute command
    match cli.command {
        // Standalone commands (no vault unlock needed)
        Commands::Init(args) => init::execute(args),
        Commands::Mounts(args) => mounts::execute(&args),
        Commands::Stats(args) => stats::run(&args),
        Commands::Completions(args) => completions::execute(&args),

        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
        Commands::Mount(args) => {
            let password = get_passphrase(&password_opts)?;
            mount::execute(&args, &password)
        }
        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
        Commands::Unmount(args) => unmount::execute(&args),
        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
        Commands::Backends(args) => backends::execute(&args),
        #[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav", feature = "nfs", feature = "fileprovider"))]
        Commands::Exec(args) => {
            let password = get_passphrase(&password_opts)?;
            exec::execute(&args, &password)
        }

        // Vault commands (require unlock)
        Commands::Ls(cmd) => execute_vault_command(&cmd, &password_opts, ls::execute),
        Commands::Cat(cmd) => execute_vault_command(&cmd, &password_opts, cat::execute),
        Commands::Tree(cmd) => execute_vault_command(&cmd, &password_opts, tree::execute),
        Commands::Mkdir(cmd) => execute_vault_command(&cmd, &password_opts, mkdir::execute),
        Commands::Touch(cmd) => execute_vault_command(&cmd, &password_opts, touch::execute),
        Commands::Write(cmd) => execute_vault_command(&cmd, &password_opts, write::execute),
        Commands::Rm(cmd) => execute_vault_command(&cmd, &password_opts, rm::execute),
        Commands::Cp(cmd) => execute_vault_command(&cmd, &password_opts, cp::execute),
        Commands::Mv(cmd) => execute_vault_command(&cmd, &password_opts, mv::execute),
        Commands::Import(cmd) => execute_vault_command(&cmd, &password_opts, import::execute),
        Commands::Export(cmd) => execute_vault_command(&cmd, &password_opts, export::execute),
        Commands::Info(cmd) => execute_info_command(&cmd, &password_opts),
    }
}

/// Execute a command that requires an unlocked vault
fn execute_vault_command<T, F>(cmd: &VaultCommand<T>, password_opts: &PasswordOptions, f: F) -> Result<()>
where
    T: clap::Args,
    F: FnOnce(&VaultOperations, &T) -> Result<()>,
{
    let vault_path = resolve_vault_path(&cmd.vault)?;
    let vault_ops = unlock_vault(&vault_path, password_opts)?;
    f(&vault_ops, &cmd.args)
}

/// Special handler for info command (needs claims, not vault_ops)
fn execute_info_command(cmd: &VaultCommand<info::Args>, password_opts: &PasswordOptions) -> Result<()> {
    let vault_path = resolve_vault_path(&cmd.vault)?;
    let passphrase = get_passphrase(password_opts)?;

    let master_key = extract_master_key(&vault_path, &passphrase)
        .context("Failed to extract master key - check your passphrase")?;

    let vault_config_path = vault_path.join("vault.cryptomator");
    let vault_config = fs::read_to_string(&vault_config_path)
        .with_context(|| format!("Failed to read vault config: {}", vault_config_path.display()))?;
    let claims = validate_vault_claims(&vault_config, &master_key)
        .context("Failed to validate vault configuration")?;

    info::execute(&vault_path, &claims, &cmd.args)
}

/// Resolve vault path, handling @alias syntax
fn resolve_vault_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();

    // Use config module for alias resolution
    let resolved = config::resolve_vault_alias(&path_str)?;

    // Validate vault path exists (non-alias paths need this check)
    if !resolved.exists() {
        anyhow::bail!("Vault path does not exist: {}", resolved.display());
    }
    if !resolved.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", resolved.display());
    }

    Ok(resolved)
}

/// Get passphrase using the priority chain:
/// 1. --password-stdin
/// 2. --password-fd
/// 3. --password / OXCRYPT_PASSWORD
/// 4. Interactive prompt
fn get_passphrase(opts: &PasswordOptions) -> Result<String> {
    if opts.password_stdin {
        read_password_from_stdin()
    } else if let Some(fd) = opts.password_fd {
        read_password_from_fd(fd)
    } else if let Some(ref password) = opts.password {
        Ok(password.clone())
    } else {
        auth::prompt_passphrase()
    }
}

/// Read password from stdin (first line only)
fn read_password_from_stdin() -> Result<String> {
    // Check if stdin has data (not a TTY)
    if io::stdin().is_terminal() {
        anyhow::bail!(
            "--password-stdin requires password to be piped in.\n\
             Example: echo \"$SECRET\" | oxcrypt --password-stdin ls ~/vault /"
        );
    }

    let mut password = String::new();
    io::stdin().read_line(&mut password)?;

    // Trim trailing newline
    let password = password.trim_end_matches('\n').trim_end_matches('\r');

    if password.is_empty() {
        anyhow::bail!("Password from stdin is empty");
    }

    Ok(password.to_string())
}

/// Read password from a file descriptor
#[cfg(unix)]
#[allow(unsafe_code)]
fn read_password_from_fd(fd: i32) -> Result<String> {
    use std::os::unix::io::FromRawFd;

    // SAFETY: The user is responsible for providing a valid, open file descriptor.
    // We trust the --password-fd flag value as it's explicitly passed by the user.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let mut password = String::new();
    file.read_to_string(&mut password)?;

    // Don't close the FD when we're done (it was passed to us)
    std::mem::forget(file);

    let password = password.trim();
    if password.is_empty() {
        anyhow::bail!("Password from file descriptor {fd} is empty");
    }

    Ok(password.to_string())
}

#[cfg(not(unix))]
fn read_password_from_fd(_fd: i32) -> Result<String> {
    anyhow::bail!("--password-fd is only supported on Unix systems");
}

/// Unlock a vault and return VaultOperations handle
fn unlock_vault(vault_path: &Path, password_opts: &PasswordOptions) -> Result<VaultOperations> {
    let passphrase = get_passphrase(password_opts)?;

    let master_key = extract_master_key(vault_path, &passphrase)
        .context("Failed to extract master key - check your passphrase")?;

    let vault_config_path = vault_path.join("vault.cryptomator");
    let vault_config = fs::read_to_string(&vault_config_path)
        .with_context(|| format!("Failed to read vault config: {}", vault_config_path.display()))?;
    let claims = validate_vault_claims(&vault_config, &master_key)
        .context("Failed to validate vault configuration")?;

    let cipher_combo = claims.cipher_combo()
        .ok_or_else(|| anyhow::anyhow!("Unsupported cipher combo: {}", claims.cipher_combo_str()))?;

    Ok(VaultOperations::with_options(
        vault_path,
        master_key,
        claims.shortening_threshold(),
        cipher_combo,
    ))
}

/// Set up tracing/logging based on verbosity level
fn setup_tracing(verbose: u8) {
    let filter = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    #[cfg(feature = "tokio-console")]
    {
        use tracing_subscriber::Layer;
        use std::net::SocketAddr;

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
                .with(tracing_subscriber::fmt::layer().with_writer(io::stderr).with_filter(fmt_filter))
                .init();
            tracing::info!("tokio-console enabled, connect with: tokio-console http://127.0.0.1:{}", console_port);
        } else {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(io::stderr).with_filter(fmt_filter))
                .init();
            tracing::warn!(
                "tokio-console port {} already in use, running without console instrumentation.",
                console_port
            );
        }
    }

    #[cfg(not(feature = "tokio-console"))]
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with_writer(io::stderr)
        .init();
}

/// Categorize an error into an exit code using typed error downcasting
///
/// This approach is more robust than string matching because it doesn't depend
/// on error message wording, which could change between versions.
fn categorize_error(e: &anyhow::Error) -> u8 {
    // Check the error chain for specific error types
    for cause in e.chain() {
        // Authentication failures (wrong password)
        if let Some(crypto_err) = cause.downcast_ref::<CryptoError>()
            && matches!(
                crypto_err,
                CryptoError::KeyUnwrapIntegrityFailed | CryptoError::KeyDerivationFailed(_)
            ) {
                return exit_code::AUTH_FAILED;
            }

        // Master key extraction errors (often wrap crypto errors)
        if let Some(mk_err) = cause.downcast_ref::<MasterKeyExtractionError>() {
            if matches!(mk_err, MasterKeyExtractionError::Crypto(_)) {
                return exit_code::AUTH_FAILED;
            }
            if matches!(mk_err, MasterKeyExtractionError::MasterKeyFileNotFound(_)) {
                return exit_code::NOT_FOUND;
            }
        }

        // Vault operation errors
        if let Some(vault_err) = cause.downcast_ref::<VaultOperationError>() {
            match vault_err {
                VaultOperationError::PathNotFound { .. }
                | VaultOperationError::FileNotFound { .. }
                | VaultOperationError::DirectoryNotFound { .. }
                | VaultOperationError::SymlinkNotFound { .. } => {
                    return exit_code::NOT_FOUND;
                }
                VaultOperationError::InvalidVaultStructure { .. } => {
                    return exit_code::VAULT_INVALID;
                }
                VaultOperationError::Io { source, .. } => {
                    if source.kind() == io::ErrorKind::PermissionDenied {
                        return exit_code::PERMISSION_DENIED;
                    }
                    if source.kind() == io::ErrorKind::NotFound {
                        return exit_code::NOT_FOUND;
                    }
                }
                _ => {}
            }
        }

        // Mount errors
        if let Some(mount_err) = cause.downcast_ref::<MountError>() {
            match mount_err {
                MountError::MountPointNotFound(_) => return exit_code::NOT_FOUND,
                MountError::Mount(io_err) => {
                    if io_err.kind() == io::ErrorKind::PermissionDenied {
                        return exit_code::PERMISSION_DENIED;
                    }
                }
                _ => return exit_code::MOUNT_FAILED,
            }
        }

        // Generic I/O errors
        if let Some(io_err) = cause.downcast_ref::<io::Error>() {
            match io_err.kind() {
                io::ErrorKind::PermissionDenied => return exit_code::PERMISSION_DENIED,
                io::ErrorKind::NotFound => return exit_code::NOT_FOUND,
                io::ErrorKind::Interrupted => return exit_code::CANCELLED,
                _ => {}
            }
        }
    }

    // Fallback to string matching for errors we don't have typed variants for
    // This catches edge cases and third-party library errors
    let msg = format!("{e:#}").to_lowercase();
    if msg.contains("cancelled") || msg.contains("interrupted") {
        exit_code::CANCELLED
    } else if msg.contains("vault") && (msg.contains("invalid") || msg.contains("corrupt")) {
        exit_code::VAULT_INVALID
    } else {
        exit_code::GENERAL_ERROR
    }
}

/// Proactively clean up stale mounts from previous sessions.
fn proactive_cleanup() -> Result<()> {
    let state_manager = MountStateManager::new()?;
    let state = state_manager.load()?;

    if state.mounts.is_empty() {
        return Ok(());
    }

    let tracked_mounts: Vec<TrackedMountInfo> = state
        .mounts
        .iter()
        .map(|e| TrackedMountInfo {
            mountpoint: e.mountpoint.clone(),
            pid: e.pid,
        })
        .collect();

    let options = CleanupOptions {
        cleanup_orphans: true,
        ..CleanupOptions::default()
    };
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
