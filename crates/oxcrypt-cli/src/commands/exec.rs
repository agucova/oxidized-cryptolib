//! Exec command - mount vault, run command, then unmount.
//!
//! This command provides a convenient way to run a command with
//! access to vault contents without leaving the mount active.
//!
//! Example:
//! ```bash
//! oxcrypt exec ~/vault -- grep -r "secret" .
//! oxcrypt exec ~/vault -- tar -cvf backup.tar .
//! oxcrypt exec ~/vault -- bash  # interactive shell
//! ```

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::instrument;

use oxcrypt_mount::{
    BackendType, MountBackend, MountHandle,
    first_available_backend, select_backend,
};

#[cfg(feature = "fuse")]
use oxcrypt_fuse::FuseBackend;

#[cfg(feature = "fskit")]
use oxcrypt_fskit::FskitBackend;

#[cfg(feature = "webdav")]
use oxcrypt_webdav::WebDavBackend;

#[cfg(feature = "nfs")]
use oxcrypt_nfs::NfsBackend;

use super::mount::BackendArg;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Path to the Cryptomator vault
    pub vault: PathBuf,

    /// Backend to use for mounting
    #[arg(short, long, value_enum)]
    pub backend: Option<BackendArg>,

    /// Mount read-only
    #[arg(long)]
    pub read_only: bool,

    /// Command and arguments to execute
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

/// Build the list of available backends
fn build_backends() -> Vec<Box<dyn MountBackend>> {
    let mut backends: Vec<Box<dyn MountBackend>> = Vec::new();

    // FSKit first on macOS 15.4+ (preferred native backend)
    #[cfg(feature = "fskit")]
    {
        backends.push(Box::new(FskitBackend::new()));
    }

    #[cfg(feature = "fuse")]
    {
        backends.push(Box::new(FuseBackend::new()));
    }

    #[cfg(feature = "webdav")]
    {
        backends.push(Box::new(WebDavBackend::new()));
    }

    #[cfg(feature = "nfs")]
    {
        backends.push(Box::new(NfsBackend::new()));
    }

    backends
}

#[instrument(level = "info", name = "cmd::exec", skip_all, fields(vault = %args.vault.display()))]
pub fn execute(args: &Args, password: &str) -> Result<()> {
    // Validate vault path
    if !args.vault.exists() {
        anyhow::bail!("Vault path does not exist: {}", args.vault.display());
    }
    if !args.vault.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", args.vault.display());
    }

    // Create temporary mountpoint
    let temp_dir = std::env::temp_dir();
    let mount_id = uuid::Uuid::new_v4();
    let mountpoint = temp_dir.join(format!("oxcrypt-exec-{mount_id}"));

    std::fs::create_dir_all(&mountpoint)
        .with_context(|| format!("Failed to create temp mountpoint: {}", mountpoint.display()))?;

    // Get backend
    let backends = build_backends();
    if backends.is_empty() {
        anyhow::bail!("No mount backends enabled. Rebuild with --features fuse, --features webdav, or --features nfs");
    }

    let backend = match args.backend {
        Some(arg) => {
            let backend_type: BackendType = arg.into();
            select_backend(&backends, backend_type).context("Failed to get mount backend")?
        }
        None => {
            first_available_backend(&backends).context("No mount backend available")?
        }
    };

    eprintln!("Mounting vault with {} backend...", backend.name());

    // Generate vault ID
    let vault_id = args.vault
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");

    // Mount the vault
    let handle: Box<dyn MountHandle> = backend
        .mount(vault_id, &args.vault, password, &mountpoint)
        .context("Failed to mount vault")?;

    eprintln!("Mounted at {}", mountpoint.display());

    // Set up cleanup on signal
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let _mp_for_signal = mountpoint.clone();

    ctrlc::set_handler(move || {
        eprintln!("\nReceived interrupt, cleaning up...");
        r.store(false, Ordering::SeqCst);
        // Note: actual cleanup happens in the main thread
    })
    .context("Failed to set signal handler")?;

    // Run the command
    let (program, cmd_args) = args.command.split_first()
        .ok_or_else(|| anyhow::anyhow!("No command specified"))?;

    eprintln!("Running: {} {}", program, cmd_args.join(" "));
    eprintln!();

    let status = Command::new(program)
        .args(cmd_args)
        .current_dir(&mountpoint)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to execute command: {program}"))?;

    // Cleanup: unmount and remove temp dir
    eprintln!();
    eprintln!("Unmounting...");

    if let Err(e) = handle.unmount() {
        eprintln!("Warning: Failed to unmount cleanly: {e}");
        // Try force unmount
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("diskutil")
                .args(["unmount", "force"])
                .arg(&mountpoint)
                .status();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("fusermount")
                .args(["-uz"])
                .arg(&mountpoint)
                .status();
        }
    }

    // Remove temp directory
    if let Err(e) = std::fs::remove_dir(&mountpoint) {
        tracing::debug!("Failed to remove temp dir: {}", e);
    }

    // Exit with the command's exit code
    if status.success() {
        Ok(())
    } else {
        let code = status.code().unwrap_or(1);
        anyhow::bail!("Command exited with status {code}");
    }
}
