//! Oxidized Vault - Desktop GUI for Cryptomator vault management
//!
//! A Dioxus-based desktop application for managing Cryptomator vaults with
//! support for multiple filesystem backends (FUSE, FSKit).

// Allow unsafe code for objc2 interop (SF Symbols on macOS)
#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]

mod app;
mod backend;
mod components;
mod dialogs;
mod error;
mod icons;
mod menu;
mod platform;
mod state;
mod tray;
mod windows;

pub use platform::{current_platform, Platform};

use crossbeam_channel::Receiver;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
#[cfg(feature = "tokio-console")]
use tracing_subscriber::layer::SubscriberExt;

use menu::MenuBarEvent;
use oxidized_mount_common::{cleanup_stale_mounts, CleanupAction, CleanupOptions, TrackedMountInfo};
use tray::{TrayEvent, TrayManager};

/// Global tray event receiver for the app to poll
static TRAY_RECEIVER: OnceLock<Receiver<TrayEvent>> = OnceLock::new();

/// Get the global tray event receiver
pub fn tray_receiver() -> Option<&'static Receiver<TrayEvent>> {
    TRAY_RECEIVER.get()
}

/// Get the global menu event receiver
pub fn menu_receiver() -> Option<&'static Receiver<MenuBarEvent>> {
    menu::menu_receiver()
}

fn main() {
    // Initialize tracing for logging
    #[cfg(feature = "tokio-console")]
    {
        // console_subscriber::spawn() returns a layer with its own built-in filter
        // for tokio instrumentation. We use per-layer filtering so the fmt layer
        // gets our custom filter while console uses its own.
        //
        // Use port 6670 for GUI to avoid conflicts with CLI tools using default 6669.
        use tracing_subscriber::Layer;
        use std::net::SocketAddr;

        let console_port: u16 = std::env::var("TOKIO_CONSOLE_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6670); // GUI uses 6670 by default, CLI uses 6669

        let console_addr: SocketAddr = ([127, 0, 0, 1], console_port).into();

        // Check if port is available before starting console subscriber
        let port_available = std::net::TcpListener::bind(console_addr).is_ok();

        let fmt_filter = EnvFilter::from_default_env()
            .add_directive("oxidized_gui=info".parse().unwrap());

        if port_available {
            let console_layer = console_subscriber::ConsoleLayer::builder()
                .server_addr(console_addr)
                .spawn();
            tracing_subscriber::registry()
                .with(console_layer)
                .with(fmt::layer().with_filter(fmt_filter))
                .init();
            tracing::info!("tokio-console enabled, connect with: tokio-console http://127.0.0.1:{}", console_port);
        } else {
            // Port in use - start without console subscriber
            tracing_subscriber::registry()
                .with(fmt::layer().with_filter(fmt_filter))
                .init();
            tracing::warn!(
                "tokio-console port {} already in use, running without console instrumentation. \
                 Set TOKIO_CONSOLE_PORT to use a different port.",
                console_port
            );
        }
    }

    #[cfg(not(feature = "tokio-console"))]
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("oxidized_gui=info".parse().unwrap()))
        .init();

    tracing::info!("Starting Oxidized Vault");

    // Proactive cleanup of stale mounts from previous sessions (non-fatal)
    if let Err(e) = proactive_cleanup() {
        tracing::warn!("Stale mount cleanup failed: {}", e);
    }

    // Set up signal handler for graceful shutdown (Cmd+Q, Dock quit, etc.)
    if let Err(e) = ctrlc::set_handler(|| backend::cleanup_and_exit()) {
        tracing::warn!("Failed to set signal handler: {}", e);
    }

    // Initialize the menu event channel
    menu::init_menu_events();
    tracing::info!("Menu event handler initialized");

    // Build the custom menu bar
    let custom_menu = menu::build_menu_bar();
    tracing::info!("Custom menu bar built");

    // Initialize the system tray
    let _tray_manager = match TrayManager::new() {
        Ok(manager) => {
            tracing::info!("System tray initialized");
            // Store the event receiver globally
            let _ = TRAY_RECEIVER.set(manager.event_receiver().clone());
            Some(manager)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize system tray: {}", e);
            None
        }
    };

    // Build desktop config
    let mut config = dioxus::desktop::Config::new()
        .with_window(
            dioxus::desktop::WindowBuilder::new()
                .with_title("Oxidized Vault")
                .with_inner_size(dioxus::desktop::LogicalSize::new(900.0, 600.0))
                .with_min_inner_size(dioxus::desktop::LogicalSize::new(600.0, 400.0))
                .with_resizable(true),
        )
        .with_menu(custom_menu)
        .with_close_behaviour(dioxus::desktop::WindowCloseBehaviour::WindowHides);

    // Register SF Symbol protocol on macOS
    #[cfg(target_os = "macos")]
    {
        config = config.with_custom_protocol("sfsymbol", icons::handle_sfsymbol_request);
        tracing::info!("SF Symbol protocol registered");
    }

    // Launch the Dioxus desktop application
    dioxus::LaunchBuilder::new()
        .with_cfg(config)
        .launch(app::App);

    // Fallback cleanup if launch() returns normally (shouldn't happen with WindowHides)
    backend::cleanup_and_exit();
}

/// Proactively clean up stale mounts from previous sessions.
///
/// This runs at GUI startup to detect and clean up mounts that were left behind
/// from crashed processes or killed daemons. It's non-fatal - errors are logged
/// but don't prevent GUI operation.
///
/// # Safety
///
/// This function NEVER unmounts:
/// - Active mounts (process still alive)
/// - Foreign mounts (not created by oxidized-cryptolib)
/// - Orphaned mounts (ours but not tracked) - only warns about these
fn proactive_cleanup() -> anyhow::Result<()> {
    // Use the shared state file from ~/.config/oxcrypt/mounts.json
    let dirs = directories::ProjectDirs::from("com", "oxidized", "oxcrypt")
        .ok_or_else(|| anyhow::anyhow!("Failed to determine config directory"))?;
    let state_path = dirs.config_dir().join("mounts.json");

    // If no state file exists, nothing to clean up
    if !state_path.exists() {
        return Ok(());
    }

    // Load the state file directly (we don't need to modify it here)
    let contents = std::fs::read_to_string(&state_path)?;
    let state: serde_json::Value = serde_json::from_str(&contents)?;

    let mounts = state
        .get("mounts")
        .and_then(|v| v.as_array())
        .map(|arr| arr.to_vec())
        .unwrap_or_default();

    if mounts.is_empty() {
        return Ok(());
    }

    // Convert state entries to TrackedMountInfo for cleanup
    let tracked_mounts: Vec<TrackedMountInfo> = mounts
        .iter()
        .filter_map(|m| {
            let mountpoint = m.get("mountpoint")?.as_str()?;
            let pid = m.get("pid")?.as_u64()? as u32;
            Some(TrackedMountInfo {
                mountpoint: PathBuf::from(mountpoint),
                pid,
            })
        })
        .collect();

    if tracked_mounts.is_empty() {
        return Ok(());
    }

    let options = CleanupOptions::default();
    let results = cleanup_stale_mounts(&tracked_mounts, &options)?;

    // Collect mountpoints that were cleaned or removed from state
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
                // Still remove from state - the mount is likely already gone
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
                // Orphaned mount - warn in logs (no stderr for GUI)
                tracing::warn!(
                    "Orphaned mount detected at {} (use 'diskutil unmount force' to remove)",
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

    // Remove cleaned mounts from state file (with file locking for safety)
    if !removed_mountpoints.is_empty() {
        remove_from_state_file(&state_path, &removed_mountpoints)?;
    }

    Ok(())
}

/// Remove mountpoints from the state file with file locking.
fn remove_from_state_file(state_path: &std::path::Path, mountpoints: &[PathBuf]) -> anyhow::Result<()> {
    use fs2::FileExt;
    use std::fs::OpenOptions;

    let lock_path = state_path.with_extension("lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    // Acquire exclusive lock with timeout
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);
    loop {
        match lock_file.try_lock_exclusive() {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > timeout {
                    anyhow::bail!("Timed out waiting for state file lock");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Read current state
    let contents = std::fs::read_to_string(state_path)?;
    let mut state: serde_json::Value = serde_json::from_str(&contents)?;

    // Remove the mountpoints
    if let Some(mounts) = state.get_mut("mounts").and_then(|v| v.as_array_mut()) {
        mounts.retain(|m| {
            m.get("mountpoint")
                .and_then(|v| v.as_str())
                .map(|mp| !mountpoints.iter().any(|p| p == std::path::Path::new(mp)))
                .unwrap_or(true)
        });
    }

    // Write back
    let contents = serde_json::to_string_pretty(&state)?;
    std::fs::write(state_path, contents)?;

    let _ = lock_file.unlock();
    Ok(())
}
