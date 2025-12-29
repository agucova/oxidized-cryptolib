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

#[cfg(feature = "tokio-console")]
use tokio::runtime::Handle;

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

    // When tokio-console is enabled, we need to run with an async runtime
    // so that the filesystem uses the instrumented runtime for visibility.
    #[cfg(feature = "tokio-console")]
    {
        use tracing_subscriber::Layer;
        use std::net::SocketAddr;

        // Build the multi-threaded runtime FIRST, before setting up tracing
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;

        // CLI tools use port 6669 by default (GUI uses 6670)
        let console_port: u16 = std::env::var("TOKIO_CONSOLE_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6669);

        let console_addr: SocketAddr = ([127, 0, 0, 1], console_port).into();
        let port_available = std::net::TcpListener::bind(console_addr).is_ok();

        let fmt_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

        if port_available {
            let console_layer = console_subscriber::ConsoleLayer::builder()
                .server_addr(console_addr)
                .spawn();
            tracing_subscriber::registry()
                .with(console_layer)
                .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter))
                .init();
            info!("tokio-console enabled, connect with: tokio-console http://127.0.0.1:{}", console_port);
        } else {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter))
                .init();
            warn!(
                "tokio-console port {} already in use, running without console instrumentation. \
                 Set TOKIO_CONSOLE_PORT to use a different port.",
                console_port
            );
        }

        // Run the mount logic, passing the runtime handle
        let handle = runtime.handle().clone();
        run_mount(cli, handle, &runtime)
    }

    #[cfg(not(feature = "tokio-console"))]
    {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
            )
            .init();

        // Run without external runtime (CryptomatorFS creates its own)
        run_mount_simple(cli)
    }
}

/// Run the mount with an external runtime handle (for tokio-console support).
#[cfg(feature = "tokio-console")]
fn run_mount(cli: Cli, handle: Handle, runtime: &tokio::runtime::Runtime) -> Result<()> {
    // Enter the runtime context so Handle::current() works
    let _guard = runtime.enter();

    // Validate paths
    if !cli.vault.exists() {
        anyhow::bail!("Vault path does not exist: {}", cli.vault.display());
    }
    if !cli.mount.exists() {
        anyhow::bail!("Mountpoint does not exist: {}", cli.mount.display());
    }

    // Get password
    let password = get_password(&cli)?;

    info!(vault = %cli.vault.display(), mount = %cli.mount.display(), "Mounting vault");

    // Create filesystem with external runtime handle for tokio-console visibility
    let fs = CryptomatorFS::with_runtime_handle(&cli.vault, &password, handle)
        .context("Failed to initialize filesystem")?;

    mount_and_wait(cli, fs)
}

/// Run the mount without external runtime (standard mode).
#[cfg(not(feature = "tokio-console"))]
fn run_mount_simple(cli: Cli) -> Result<()> {
    // Validate paths
    if !cli.vault.exists() {
        anyhow::bail!("Vault path does not exist: {}", cli.vault.display());
    }
    if !cli.mount.exists() {
        anyhow::bail!("Mountpoint does not exist: {}", cli.mount.display());
    }

    // Get password
    let password = get_password(&cli)?;

    info!(vault = %cli.vault.display(), mount = %cli.mount.display(), "Mounting vault");

    // Create filesystem (creates its own internal runtime)
    let fs = CryptomatorFS::new(&cli.vault, &password)
        .context("Failed to initialize filesystem")?;

    mount_and_wait(cli, fs)
}

/// Get password from CLI, environment, or prompt.
fn get_password(cli: &Cli) -> Result<Zeroizing<String>> {
    if let Some(ref pwd) = cli.password {
        Ok(Zeroizing::new(pwd.clone()))
    } else if let Ok(pwd) = std::env::var("VAULT_PASSWORD") {
        Ok(Zeroizing::new(pwd))
    } else {
        Ok(Zeroizing::new(
            rpassword::prompt_password("Vault password: ")
                .context("Failed to read password")?,
        ))
    }
}

/// Mount the filesystem and wait for Ctrl+C.
fn mount_and_wait(cli: Cli, fs: CryptomatorFS) -> Result<()> {
    // Derive vault name from path for display
    let vault_name = cli
        .vault
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Vault".to_string());

    // Mount options
    let mut options = vec![
        fuser::MountOption::FSName(format!("cryptomator:{}", vault_name)),
        fuser::MountOption::Subtype("oxidized".to_string()),
        fuser::MountOption::AutoUnmount,
    ];

    #[cfg(target_os = "macos")]
    options.push(fuser::MountOption::CUSTOM(format!("volname={}", vault_name)));

    if cli.read_only {
        options.push(fuser::MountOption::RO);
    } else {
        options.push(fuser::MountOption::RW);
    }

    // Set up channel for signal handling
    let (tx, rx) = mpsc::channel::<()>();

    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("Failed to set signal handler")?;

    info!("Mounting filesystem (press Ctrl+C to unmount)");

    let session = fuser::spawn_mount2(fs, &cli.mount, &options).map_err(|e| {
        error!(error = %e, "Mount failed");
        anyhow::anyhow!("Failed to mount filesystem: {}", e)
    })?;

    info!("Filesystem mounted at {}", cli.mount.display());

    match rx.recv() {
        Ok(()) => {
            info!("Received interrupt signal, unmounting...");
        }
        Err(_) => {
            warn!("Signal channel closed unexpectedly");
        }
    }

    drop(session);
    info!("Filesystem unmounted");
    Ok(())
}
