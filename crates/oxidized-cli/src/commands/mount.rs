//! Mount command - mount a Cryptomator vault as a filesystem.
//!
//! Supports multiple backends via feature flags:
//! - `fuse`: FUSE backend (macOS with macFUSE, Linux with libfuse)
//! - `fskit`: FSKit backend (macOS 15.4+ only)

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use oxidized_cryptolib::{
    BackendInfo, BackendType, MountBackend, MountHandle,
    first_available_backend, list_backend_info, select_backend,
};

#[cfg(feature = "fuse")]
use oxidized_fuse::FuseBackend;

#[cfg(feature = "fskit")]
use oxidized_fskit::FSKitBackend;

#[cfg(feature = "webdav")]
use oxidized_webdav::WebDavBackend;

/// Backend selection for mount command
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BackendArg {
    /// Use FUSE backend (requires macFUSE on macOS or libfuse on Linux)
    #[cfg(feature = "fuse")]
    Fuse,
    /// Use FSKit backend (macOS 15.4+ only)
    #[cfg(feature = "fskit")]
    Fskit,
    /// Use WebDAV backend (no kernel extensions required)
    #[cfg(feature = "webdav")]
    Webdav,
}

impl From<BackendArg> for BackendType {
    fn from(arg: BackendArg) -> Self {
        match arg {
            #[cfg(feature = "fuse")]
            BackendArg::Fuse => BackendType::Fuse,
            #[cfg(feature = "fskit")]
            BackendArg::Fskit => BackendType::FSKit,
            #[cfg(feature = "webdav")]
            BackendArg::Webdav => BackendType::WebDav,
        }
    }
}

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Path to the Cryptomator vault
    #[arg(long, env = "OXCRYPT_VAULT")]
    pub vault: Option<PathBuf>,

    /// Directory where the vault will be mounted
    #[arg(short, long)]
    pub mountpoint: PathBuf,

    /// Backend to use for mounting (if not specified, uses first available)
    #[arg(short, long, value_enum)]
    pub backend: Option<BackendArg>,

    /// Vault passphrase
    #[arg(long, env = "OXCRYPT_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Create the mountpoint directory if it doesn't exist
    #[arg(long, default_value = "false")]
    pub create_mountpoint: bool,
}

/// Build the list of available backends based on enabled features
///
/// Backends are ordered by preference: FSKit first (better macOS integration),
/// then FUSE, then WebDAV as fallback. This order is used for auto-selection.
fn build_backends() -> Vec<Box<dyn MountBackend>> {
    let mut backends: Vec<Box<dyn MountBackend>> = Vec::new();

    // FSKit preferred on macOS 15.4+ (better integration, no kernel extension)
    #[cfg(feature = "fskit")]
    {
        backends.push(Box::new(FSKitBackend::new()));
    }

    // FUSE as second choice (cross-platform, requires kernel extension)
    #[cfg(feature = "fuse")]
    {
        backends.push(Box::new(FuseBackend::new()));
    }

    // WebDAV as last fallback (no kernel extensions, HTTP-based)
    #[cfg(feature = "webdav")]
    {
        backends.push(Box::new(WebDavBackend::new()));
    }

    backends
}

pub fn execute(args: Args, vault_path: Option<PathBuf>) -> Result<()> {
    // Get vault path from args or global flag
    let vault_path = args
        .vault
        .or(vault_path)
        .ok_or_else(|| anyhow::anyhow!("--vault is required (or set OXCRYPT_VAULT)"))?;

    // Validate vault path
    if !vault_path.exists() {
        anyhow::bail!("Vault path does not exist: {}", vault_path.display());
    }
    if !vault_path.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", vault_path.display());
    }

    // Get passphrase
    let password = match args.password {
        Some(p) => p,
        None => crate::auth::prompt_passphrase()?,
    };

    // Handle mountpoint
    let mountpoint = &args.mountpoint;
    if !mountpoint.exists() {
        if args.create_mountpoint {
            std::fs::create_dir_all(mountpoint)
                .with_context(|| format!("Failed to create mountpoint: {}", mountpoint.display()))?;
        } else {
            anyhow::bail!(
                "Mountpoint does not exist: {}. Use --create-mountpoint to create it.",
                mountpoint.display()
            );
        }
    }

    // Get backend
    let backends = build_backends();
    if backends.is_empty() {
        anyhow::bail!("No mount backends enabled. Rebuild with --features fuse, --features fskit, or --features webdav");
    }

    let backend = match args.backend {
        Some(arg) => {
            let backend_type: BackendType = arg.into();
            select_backend(&backends, backend_type).context("Failed to get mount backend")?
        }
        None => {
            // Use first available backend (ordered by preference in build_backends)
            first_available_backend(&backends).context("No mount backend available")?
        }
    };

    eprintln!("Using {} backend", backend.name());

    // Generate a vault ID from the path
    let vault_id = vault_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");

    // Mount the vault
    eprintln!("Mounting vault at {}...", mountpoint.display());
    let handle: Box<dyn MountHandle> = backend
        .mount(vault_id, &vault_path, &password, mountpoint)
        .context("Failed to mount vault")?;

    eprintln!("Vault mounted at {}", handle.mountpoint().display());
    eprintln!("Press Ctrl+C to unmount and exit");

    // Set up signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        eprintln!("\nReceived interrupt signal, unmounting...");
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set signal handler")?;

    // Wait for signal
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Unmount
    eprintln!("Unmounting...");
    handle.unmount().context("Failed to unmount")?;
    eprintln!("Unmounted successfully");

    Ok(())
}

/// List available backends and their status
pub fn list_backends() -> Vec<BackendInfo> {
    list_backend_info(&build_backends())
}
