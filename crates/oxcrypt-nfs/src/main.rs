//! NFS mount command for Cryptomator vaults.
//!
//! This binary provides a standalone NFS mount command similar to `oxmount` for FUSE.
//!
//! ## Debugging with tokio-console
//!
//! Build with the `tokio-console` feature for async task introspection:
//! ```bash
//! cargo build -p oxcrypt-nfs --features tokio-console
//! ```
//!
//! Then run `tokio-console` in another terminal to connect (default: 127.0.0.1:6669).

// Use mimalloc for reduced allocation latency (enabled by default).
// Disable with `--no-default-features` if debugging allocator issues.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::Parser;
use oxcrypt_mount::MountBackend;
use oxcrypt_nfs::NfsBackend;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
#[cfg(feature = "tokio-console")]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    #[cfg(feature = "tokio-console")]
    {
        // console_subscriber returns a layer with its own built-in filter for tokio
        // instrumentation. We use per-layer filtering so the fmt layer gets our
        // custom filter while console uses its own.
        use tracing_subscriber::Layer;
        use std::net::SocketAddr;

        // CLI tools use port 6669 by default (GUI uses 6670)
        let console_port: u16 = std::env::var("TOKIO_CONSOLE_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6669);

        let console_addr: SocketAddr = ([127, 0, 0, 1], console_port).into();
        let port_available = std::net::TcpListener::bind(console_addr).is_ok();

        let fmt_filter = EnvFilter::from_default_env();

        if port_available {
            let console_layer = console_subscriber::ConsoleLayer::builder()
                .server_addr(console_addr)
                .spawn();
            tracing_subscriber::registry()
                .with(console_layer)
                .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter))
                .init();
            tracing::info!("tokio-console enabled, connect with: tokio-console http://127.0.0.1:{}", console_port);
        } else {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter))
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
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Get password
    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Vault password: ")?,
    };

    if !args.vault.exists() {
        anyhow::bail!("Vault path does not exist: {}", args.vault.display());
    }
    if !args.vault.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", args.vault.display());
    }

    if !args.mountpoint.exists() {
        std::fs::create_dir_all(&args.mountpoint).with_context(|| {
            format!(
                "Failed to create mountpoint: {}",
                args.mountpoint.display()
            )
        })?;
    }
    if !args.mountpoint.is_dir() {
        anyhow::bail!(
            "Mountpoint is not a directory: {}",
            args.mountpoint.display()
        );
    }

    let backend = match args.port {
        Some(port) => NfsBackend::with_port(port),
        None => NfsBackend::new(),
    };

    if !backend.is_available() {
        let reason = backend
            .unavailable_reason()
            .unwrap_or_else(|| "NFS backend is unavailable".to_string());
        anyhow::bail!(reason);
    }

    let vault_id = args
        .vault
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");

    tracing::info!(
        vault = ?args.vault,
        mountpoint = ?args.mountpoint,
        port = ?args.port,
        "Starting NFS mount"
    );

    let handle = backend
        .mount(vault_id, &args.vault, &password, &args.mountpoint)
        .context("Failed to mount vault")?;

    tracing::info!(mountpoint = ?handle.mountpoint(), "Vault mounted");
    tracing::info!("Press Ctrl+C to unmount and exit");

    tokio::signal::ctrl_c()
        .await
        .context("Failed to wait for Ctrl+C")?;

    tracing::info!("Received interrupt signal, unmounting...");
    handle.unmount().context("Failed to unmount")?;

    tracing::info!("Unmounted successfully");
    Ok(())
}
