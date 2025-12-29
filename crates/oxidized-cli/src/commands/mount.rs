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

#[cfg(feature = "nfs")]
use oxidized_nfs::NfsBackend;

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
    /// Use NFS backend (local NFSv3 server, no kernel extensions)
    #[cfg(feature = "nfs")]
    Nfs,
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
            #[cfg(feature = "nfs")]
            BackendArg::Nfs => BackendType::Nfs,
        }
    }
}

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Path to the Cryptomator vault
    #[arg(long, env = "OXCRYPT_VAULT")]
    pub vault: Option<PathBuf>,

    /// Directory where the vault will be mounted
    #[arg(short, long, required_unless_present = "here")]
    pub mountpoint: Option<PathBuf>,

    /// Mount in current directory using vault name (e.g., ./my-vault)
    #[arg(long, conflicts_with = "mountpoint")]
    pub here: bool,

    /// Backend to use for mounting (if not specified, uses first available)
    #[arg(short, long, value_enum)]
    pub backend: Option<BackendArg>,

    /// Vault passphrase
    #[arg(long, env = "OXCRYPT_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Create the mountpoint directory if it doesn't exist
    #[arg(long, default_value = "false")]
    pub create_mountpoint: bool,

    /// Run mount in background (daemon mode)
    #[arg(short, long)]
    pub daemon: bool,

    /// Internal flag: this process is the daemon child (don't spawn again)
    #[arg(long, hide = true)]
    pub internal_daemon_child: bool,
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

    // WebDAV as fallback (no kernel extensions, HTTP-based)
    #[cfg(feature = "webdav")]
    {
        backends.push(Box::new(WebDavBackend::new()));
    }

    // NFS as alternative (no kernel extensions, NFSv3)
    #[cfg(feature = "nfs")]
    {
        backends.push(Box::new(NfsBackend::new()));
    }

    backends
}

pub fn execute(args: Args, vault_path: Option<PathBuf>) -> Result<()> {
    // Get vault path from args or global flag
    let vault_path = args
        .vault
        .clone()
        .or(vault_path)
        .ok_or_else(|| anyhow::anyhow!("--vault is required (or set OXCRYPT_VAULT)"))?;

    // Validate vault path
    if !vault_path.exists() {
        anyhow::bail!("Vault path does not exist: {}", vault_path.display());
    }
    if !vault_path.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", vault_path.display());
    }

    // Compute mountpoint from --here or --mountpoint
    let mountpoint = if args.here {
        let vault_name = vault_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault");
        std::env::current_dir()
            .context("Failed to get current directory")?
            .join(vault_name)
    } else {
        args.mountpoint
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--mountpoint is required (or use --here)"))?
    };

    // Handle daemon mode: spawn child process and exit
    if args.daemon && !args.internal_daemon_child {
        return spawn_daemon_mount(&args, &vault_path, &mountpoint);
    }

    // Get passphrase
    let password = match args.password {
        Some(ref p) => p.clone(),
        None => crate::auth::prompt_passphrase()?,
    };

    // Handle mountpoint creation
    if !mountpoint.exists() {
        if args.create_mountpoint || args.here {
            std::fs::create_dir_all(&mountpoint)
                .with_context(|| format!("Failed to create mountpoint: {}", mountpoint.display()))?;
        } else if mountpoint.parent().map(|p| p.exists()).unwrap_or(false) {
            anyhow::bail!(
                "Mountpoint does not exist: {}\n\
                 Parent directory exists - use --create-mountpoint to create it.",
                mountpoint.display()
            );
        } else {
            anyhow::bail!(
                "Mountpoint does not exist: {}\n\
                 Create the parent directory first, or use --here to mount in current directory.",
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
        .mount(vault_id, &vault_path, &password, &mountpoint)
        .context("Failed to mount vault")?;

    eprintln!("Vault mounted at {}", handle.mountpoint().display());

    // Register in state file
    let state_manager = crate::state::MountStateManager::new()
        .context("Failed to initialize state manager")?;
    let mount_entry = crate::state::MountEntry::new(
        vault_path.clone(),
        mountpoint.clone(),
        backend.id(),
        std::process::id(),
        args.internal_daemon_child,
    );
    state_manager
        .add_mount(mount_entry)
        .context("Failed to register mount in state file")?;

    if args.internal_daemon_child {
        eprintln!("Daemon mount started (PID: {})", std::process::id());
    } else {
        eprintln!("Press Ctrl+C to unmount and exit");
    }

    // Set up signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let mountpoint_for_cleanup = mountpoint.clone();

    ctrlc::set_handler(move || {
        eprintln!("\nReceived interrupt signal, unmounting...");
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set signal handler")?;

    // Wait for signal
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Remove from state file before unmounting
    if let Ok(manager) = crate::state::MountStateManager::new() {
        let _ = manager.remove_by_mountpoint(&mountpoint_for_cleanup);
    }

    // Unmount
    eprintln!("Unmounting...");
    handle.unmount().context("Failed to unmount")?;
    eprintln!("Unmounted successfully");

    Ok(())
}

/// Spawn a daemon process to run the mount in background.
fn spawn_daemon_mount(args: &Args, vault_path: &PathBuf, mountpoint: &PathBuf) -> Result<()> {
    use std::process::{Command, Stdio};

    // Get password before spawning (interactive prompt in parent)
    let password = match &args.password {
        Some(p) => p.clone(),
        None => crate::auth::prompt_passphrase()?,
    };

    // Build command to re-invoke ourselves with --internal-daemon-child
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let mut cmd = Command::new(&exe);

    cmd.arg("mount");
    cmd.arg("--vault").arg(vault_path);
    cmd.arg("--mountpoint").arg(mountpoint);
    cmd.arg("--create-mountpoint");
    cmd.arg("--internal-daemon-child");

    if let Some(backend) = &args.backend {
        let backend_str = match backend {
            #[cfg(feature = "fuse")]
            BackendArg::Fuse => "fuse",
            #[cfg(feature = "fskit")]
            BackendArg::Fskit => "fskit",
            #[cfg(feature = "webdav")]
            BackendArg::Webdav => "webdav",
            #[cfg(feature = "nfs")]
            BackendArg::Nfs => "nfs",
        };
        cmd.arg("--backend").arg(backend_str);
    }

    // Pass password via env var (not in command line args for security)
    cmd.env("OXCRYPT_PASSWORD", &password);

    // Detach from parent
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // New process group
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let child = cmd.spawn().context("Failed to spawn daemon process")?;
    let pid = child.id();

    // Give it a moment to start and potentially fail
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if the mount appeared
    if mountpoint.exists() && mountpoint.is_dir() {
        eprintln!("Mount started in background (PID: {})", pid);
        eprintln!("Mountpoint: {}", mountpoint.display());
        eprintln!();
        eprintln!("Use 'oxcrypt mounts' to list active mounts");
        eprintln!("Use 'oxcrypt unmount {}' to stop", mountpoint.display());
    } else {
        eprintln!("Mount daemon started (PID: {})", pid);
        eprintln!("Note: Mount may still be initializing. Use 'oxcrypt mounts' to check status.");
    }

    Ok(())
}

/// List available backends and their status
pub fn list_backends() -> Vec<BackendInfo> {
    list_backend_info(&build_backends())
}
