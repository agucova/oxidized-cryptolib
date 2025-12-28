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

use oxidized_cryptolib::{BackendType, MountBackend, MountError, MountHandle};

#[cfg(feature = "fuse")]
use oxidized_fuse::FuseBackend;

#[cfg(feature = "fskit")]
use oxidized_fskit::FSKitBackend;

/// Backend selection for mount command
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum BackendArg {
    /// Automatically select the best available backend
    #[default]
    Auto,
    /// Use FUSE backend (requires macFUSE on macOS or libfuse on Linux)
    #[cfg(feature = "fuse")]
    Fuse,
    /// Use FSKit backend (macOS 15.4+ only)
    #[cfg(feature = "fskit")]
    Fskit,
}

impl From<BackendArg> for BackendType {
    fn from(arg: BackendArg) -> Self {
        match arg {
            BackendArg::Auto => BackendType::Auto,
            #[cfg(feature = "fuse")]
            BackendArg::Fuse => BackendType::Fuse,
            #[cfg(feature = "fskit")]
            BackendArg::Fskit => BackendType::FSKit,
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

    /// Backend to use for mounting
    #[arg(short, long, value_enum, default_value = "auto")]
    pub backend: BackendArg,

    /// Vault passphrase
    #[arg(long, env = "OXCRYPT_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Create the mountpoint directory if it doesn't exist
    #[arg(long, default_value = "false")]
    pub create_mountpoint: bool,
}

/// Get a backend instance based on the selection and availability.
fn get_backend(backend_type: BackendType) -> Result<Box<dyn MountBackend>, MountError> {
    match backend_type {
        BackendType::Auto => {
            // Try FSKit first (if available and enabled), then FUSE
            #[cfg(feature = "fskit")]
            {
                let fskit = FSKitBackend::new();
                if fskit.is_available() {
                    return Ok(Box::new(fskit));
                }
            }

            #[cfg(feature = "fuse")]
            {
                let fuse = FuseBackend::new();
                if fuse.is_available() {
                    return Ok(Box::new(fuse));
                }
            }

            // Nothing available
            Err(MountError::BackendUnavailable(
                "No mount backend available. Install macFUSE/libfuse or upgrade to macOS 15.4+."
                    .to_string(),
            ))
        }

        BackendType::Fuse => {
            #[cfg(feature = "fuse")]
            {
                let backend = FuseBackend::new();
                if !backend.is_available() {
                    return Err(MountError::BackendUnavailable(
                        backend.unavailable_reason().unwrap_or_default(),
                    ));
                }
                Ok(Box::new(backend))
            }
            #[cfg(not(feature = "fuse"))]
            {
                Err(MountError::BackendUnavailable(
                    "FUSE backend not enabled. Rebuild with --features fuse".to_string(),
                ))
            }
        }

        BackendType::FSKit => {
            #[cfg(feature = "fskit")]
            {
                let backend = FSKitBackend::new();
                if !backend.is_available() {
                    return Err(MountError::BackendUnavailable(
                        backend.unavailable_reason().unwrap_or_default(),
                    ));
                }
                Ok(Box::new(backend))
            }
            #[cfg(not(feature = "fskit"))]
            {
                Err(MountError::BackendUnavailable(
                    "FSKit backend not enabled. Rebuild with --features fskit".to_string(),
                ))
            }
        }
    }
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
    let backend_type: BackendType = args.backend.into();
    let backend = get_backend(backend_type).context("Failed to get mount backend")?;

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
    let mut backends = Vec::new();

    #[cfg(feature = "fuse")]
    {
        let fuse = FuseBackend::new();
        backends.push(BackendInfo {
            id: fuse.id().to_string(),
            name: fuse.name().to_string(),
            available: fuse.is_available(),
            reason: fuse.unavailable_reason(),
        });
    }

    #[cfg(feature = "fskit")]
    {
        let fskit = FSKitBackend::new();
        backends.push(BackendInfo {
            id: fskit.id().to_string(),
            name: fskit.name().to_string(),
            available: fskit.is_available(),
            reason: fskit.unavailable_reason(),
        });
    }

    backends
}

/// Information about a mount backend
pub struct BackendInfo {
    pub id: String,
    pub name: String,
    pub available: bool,
    pub reason: Option<String>,
}
