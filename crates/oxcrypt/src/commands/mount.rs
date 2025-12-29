//! Mount command - mount a Cryptomator vault as a filesystem.
//!
//! Supports multiple backends via feature flags:
//! - `fuse`: FUSE backend (macOS with macFUSE, Linux with libfuse)
//! - `fskit`: FSKit backend (macOS 15.4+ only)
//! - `webdav`: WebDAV backend (cross-platform)
//! - `nfs`: NFS backend (cross-platform)

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use oxcrypt_mount::{
    BackendInfo, BackendType, MountBackend, MountHandle, VaultStats,
    first_available_backend, list_backend_info, select_backend,
};

use crate::ipc::{self, IpcServer};

#[cfg(feature = "fuse")]
use oxcrypt_fuse::FuseBackend;

// TODO: FSKit CLI integration needs FSKitBackend wrapper implementing MountBackend trait
// The oxcrypt-fskit crate provides CryptoFilesystem for Swift FFI, but the CLI needs
// a Rust wrapper that can mount/unmount via the Swift extension
#[cfg(feature = "fskit")]
compile_error!("FSKit CLI backend not yet implemented. Use --features fuse or webdav instead.");

#[cfg(feature = "webdav")]
use oxcrypt_webdav::WebDavBackend;

#[cfg(feature = "nfs")]
use oxcrypt_nfs::NfsBackend;

/// Backend selection for mount command
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BackendArg {
    /// Use FUSE backend (requires macFUSE on macOS or libfuse on Linux)
    #[cfg(feature = "fuse")]
    Fuse,
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
    pub vault: PathBuf,

    /// Directory where the vault will be mounted
    #[arg(value_name = "MOUNTPOINT")]
    pub mountpoint: Option<PathBuf>,

    /// Vault passphrase (insecure, prefer --password-stdin)
    #[arg(short = 'p', long, env = "OXCRYPT_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Read password from stdin (single line)
    #[arg(long, conflicts_with = "password")]
    pub password_stdin: bool,

    /// Backend to use for mounting (if not specified, uses first available)
    #[arg(short, long, value_enum)]
    pub backend: Option<BackendArg>,

    /// Run in foreground instead of daemon mode
    #[arg(short, long)]
    pub foreground: bool,

    /// Internal flag: this process is the daemon child (don't spawn again)
    #[arg(long, hide = true)]
    pub internal_daemon_child: bool,
}

/// Build the list of available backends based on enabled features
fn build_backends() -> Vec<Box<dyn MountBackend>> {
    let mut backends: Vec<Box<dyn MountBackend>> = Vec::new();

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

pub fn execute(args: Args) -> Result<()> {
    // Validate vault path
    if !args.vault.exists() {
        anyhow::bail!("Vault path does not exist: {}", args.vault.display());
    }
    if !args.vault.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", args.vault.display());
    }

    // Compute mountpoint - default to ~/Vaults/<vault-name>
    let mountpoint = match args.mountpoint.clone() {
        Some(mp) => mp,
        None => {
            let vault_name = args.vault
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("vault");
            directories::BaseDirs::new().and_then(|d| Some(d.home_dir().to_path_buf()))
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
                .join("Vaults")
                .join(vault_name)
        }
    };

    // Handle daemon mode: spawn child process and exit (unless foreground or already child)
    if !args.foreground && !args.internal_daemon_child {
        return spawn_daemon_mount(&args, &mountpoint);
    }

    // Get passphrase
    let password = get_password(&args)?;

    // Create mountpoint if needed
    if !mountpoint.exists() {
        std::fs::create_dir_all(&mountpoint)
            .with_context(|| format!("Failed to create mountpoint: {}", mountpoint.display()))?;
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
            first_available_backend(&backends).context("No mount backend available")?
        }
    };

    eprintln!("Using {} backend", backend.name());

    // Generate a vault ID from the path
    let vault_id = args.vault
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");

    // Mount the vault
    eprintln!("Mounting vault at {}...", mountpoint.display());
    let handle: Box<dyn MountHandle> = backend
        .mount(vault_id, &args.vault, &password, &mountpoint)
        .context("Failed to mount vault")?;

    eprintln!("Vault mounted at {}", handle.mountpoint().display());

    // Get stats from the mount handle (if supported by backend)
    let stats: Option<Arc<VaultStats>> = handle.stats();

    // Generate a unique mount ID for the IPC socket
    let mount_id = uuid::Uuid::new_v4().to_string();

    // Set up IPC server (only if stats are available and in daemon mode)
    let ipc_server: Option<IpcServer> = if args.internal_daemon_child {
        match ipc::socket_path_for_mount(&mount_id) {
            Ok(socket_path) => match IpcServer::new(socket_path.clone()) {
                Ok(server) => {
                    tracing::info!("IPC server started at {}", socket_path.display());
                    Some(server)
                }
                Err(e) => {
                    tracing::warn!("Failed to start IPC server: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to determine socket path: {}", e);
                None
            }
        }
    } else {
        None
    };

    let socket_path = ipc_server.as_ref().map(|s| s.socket_path().to_path_buf());

    // Register in state file
    let state_manager = crate::state::MountStateManager::new()
        .context("Failed to initialize state manager")?;
    let mount_entry = crate::state::MountEntry::new(
        args.vault.clone(),
        mountpoint.clone(),
        backend.id(),
        std::process::id(),
        args.internal_daemon_child,
        socket_path.clone(),
    );
    state_manager
        .add_mount(mount_entry)
        .context("Failed to register mount in state file")?;

    if args.internal_daemon_child {
        eprintln!("Daemon mount started (PID: {})", std::process::id());
        if let Some(ref path) = socket_path {
            eprintln!("IPC socket: {}", path.display());
        }
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

    // Main loop: wait for signal while handling IPC requests
    while running.load(Ordering::SeqCst) {
        if let (Some(server), Some(stats)) = (&ipc_server, &stats) {
            if let Err(e) = server.try_accept(|request| {
                ipc::handle_request(request, stats)
            }) {
                tracing::debug!("IPC accept error: {}", e);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Clean up IPC server socket
    if let Some(server) = ipc_server {
        let socket_path = server.socket_path().to_path_buf();
        drop(server);
        if let Err(e) = std::fs::remove_file(&socket_path) {
            tracing::debug!("Failed to remove IPC socket: {}", e);
        }
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
fn spawn_daemon_mount(args: &Args, mountpoint: &PathBuf) -> Result<()> {
    use std::process::{Command, Stdio};

    // Get password before spawning (interactive prompt in parent)
    let password = get_password(args)?;

    // Build command to re-invoke ourselves with --internal-daemon-child
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let mut cmd = Command::new(&exe);

    cmd.arg("mount");
    cmd.arg(&args.vault);
    cmd.arg(mountpoint);
    cmd.arg("--internal-daemon-child");

    if let Some(backend) = &args.backend {
        let backend_str = match backend {
            #[cfg(feature = "fuse")]
            BackendArg::Fuse => "fuse",
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
        cmd.process_group(0);
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let child = cmd.spawn().context("Failed to spawn daemon process")?;
    let pid = child.id();

    // Give it a moment to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    eprintln!("Mount started in background (PID: {})", pid);
    eprintln!("Mountpoint: {}", mountpoint.display());
    eprintln!();
    eprintln!("Use 'oxcrypt mounts' to list active mounts");
    eprintln!("Use 'oxcrypt unmount {}' to stop", mountpoint.display());

    Ok(())
}

/// Get password from args
fn get_password(args: &Args) -> Result<String> {
    if args.password_stdin {
        if io::stdin().is_terminal() {
            anyhow::bail!(
                "--password-stdin requires password to be piped in.\n\
                 Example: echo \"$SECRET\" | oxcrypt mount ~/vault /mnt/vault --password-stdin"
            );
        }
        let mut password = String::new();
        io::stdin().lock().read_line(&mut password)?;
        let password = password.trim_end_matches('\n').trim_end_matches('\r');
        if password.is_empty() {
            anyhow::bail!("Password from stdin is empty");
        }
        Ok(password.to_string())
    } else if let Some(ref password) = args.password {
        Ok(password.clone())
    } else {
        crate::auth::prompt_passphrase()
    }
}

/// List available backends and their status
pub fn list_backends() -> Vec<BackendInfo> {
    list_backend_info(&build_backends())
}
