//! FSKitBridge setup CLI tool.
//!
//! This tool manages FSKitBridge.app installation and configuration.
//! Used by CI and developers to set up FSKit support.
//!
//! # Usage
//!
//! ```bash
//! # Check FSKitBridge status
//! oxfskit-setup status
//!
//! # Download and install FSKitBridge
//! oxfskit-setup install
//!
//! # Launch FSKitBridge.app
//! oxfskit-setup launch
//!
//! # Open System Settings to enable extension
//! oxfskit-setup open-settings
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use oxidized_fskit::setup::{
    self, find_installation, get_status, launch_bridge, open_system_settings_extensions,
    remove_quarantine, BridgeStatus, BRIDGE_PORT, RELEASES_URL,
};

#[cfg(feature = "setup")]
use oxidized_fskit::setup::{download_latest, install_to};

#[derive(Parser)]
#[command(name = "oxfskit-setup")]
#[command(about = "FSKitBridge setup and management tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check FSKitBridge installation status
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Download and install FSKitBridge from GitHub releases
    #[cfg(feature = "setup")]
    Install {
        /// Installation directory (default: ~/Applications)
        #[arg(long)]
        dest: Option<PathBuf>,

        /// Skip launching after install
        #[arg(long)]
        no_launch: bool,
    },

    /// Launch FSKitBridge.app to register the extension
    Launch,

    /// Open System Settings to the File System Extensions pane
    OpenSettings,

    /// Remove quarantine attribute from FSKitBridge.app
    RemoveQuarantine {
        /// Path to FSKitBridge.app (auto-detected if not specified)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Check if FSKitBridge is responding on TCP
    Ping {
        /// Timeout in seconds
        #[arg(long, default_value = "5")]
        timeout: u64,
    },
}

fn main() -> ExitCode {
    // Initialize tracing for the setup feature
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Status { json } => cmd_status(json),
        #[cfg(feature = "setup")]
        Commands::Install { dest, no_launch } => cmd_install(dest, no_launch),
        Commands::Launch => cmd_launch(),
        Commands::OpenSettings => cmd_open_settings(),
        Commands::RemoveQuarantine { path } => cmd_remove_quarantine(path),
        Commands::Ping { timeout } => cmd_ping(timeout),
    }
}

fn cmd_status(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    let status = rt.block_on(get_status());
    let installation = find_installation();

    if json {
        let json_output = serde_json::json!({
            "status": format!("{:?}", status),
            "ready": status == BridgeStatus::Ready,
            "installation_path": installation,
            "tcp_port": BRIDGE_PORT,
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        println!("FSKitBridge Status");
        println!("==================");
        println!("Status: {status}");
        println!();

        match &installation {
            Some(path) => println!("Installation: {}", path.display()),
            None => println!("Installation: Not found"),
        }

        println!("TCP Port: {BRIDGE_PORT}");
        println!();

        match status {
            BridgeStatus::Ready => {
                println!("✓ FSKitBridge is ready for use");
            }
            BridgeStatus::UnsupportedPlatform => {
                println!("✗ FSKit requires macOS 15.4 or later");
            }
            BridgeStatus::NotInstalled => {
                println!("✗ FSKitBridge.app is not installed");
                println!();
                println!("To install, run:");
                println!("  oxfskit-setup install");
                println!();
                println!("Or download manually from:");
                println!("  {RELEASES_URL}");
            }
            BridgeStatus::Quarantined => {
                println!("✗ FSKitBridge.app has quarantine attribute");
                println!();
                println!("To remove quarantine, run:");
                println!("  oxfskit-setup remove-quarantine");
            }
            BridgeStatus::ExtensionDisabled => {
                println!("✗ FSKit extension is not enabled or not responding");
                println!();
                println!("Steps to enable:");
                println!("  1. Launch FSKitBridge.app: oxfskit-setup launch");
                println!("  2. Open System Settings:   oxfskit-setup open-settings");
                println!("  3. Enable FSKitBridge under File System Extensions");
            }
        }
    }

    // Return success only if Ready
    if status == BridgeStatus::Ready {
        Ok(())
    } else {
        Err(format!("FSKitBridge not ready: {status}").into())
    }
}

#[cfg(feature = "setup")]
fn cmd_install(
    dest: Option<PathBuf>,
    no_launch: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    let dest_dir = dest.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join("Applications"))
            .unwrap_or_else(|| PathBuf::from("/Applications"))
    });

    println!("FSKitBridge Installer");
    println!("=====================");
    println!();
    println!("Destination: {}", dest_dir.display());
    println!();

    // Check if already installed
    if let Some(existing) = find_installation() {
        println!("Note: FSKitBridge already installed at {}", existing.display());
        println!();
    }

    println!("Downloading FSKitBridge from GitHub releases...");

    let rt = tokio::runtime::Runtime::new()?;
    let app_path = rt.block_on(async {
        download_latest(|progress| {
            print!(
                "\rProgress: {:.1}% ({} / {} bytes)",
                progress.fraction * 100.0,
                progress.bytes_downloaded,
                progress.total_bytes.unwrap_or(0)
            );
            io::stdout().flush().ok();
        })
        .await
    })?;

    println!();
    println!("Download complete: {}", app_path.display());
    println!();

    // Create destination directory if needed
    if !dest_dir.exists() {
        std::fs::create_dir_all(&dest_dir)?;
        println!("Created directory: {}", dest_dir.display());
    }

    // Install
    println!("Installing to {}...", dest_dir.display());
    let installed_path = rt.block_on(install_to(&app_path, &dest_dir))?;
    println!("Installed: {}", installed_path.display());

    // Clean up temp download
    if app_path.exists() {
        let _ = std::fs::remove_dir_all(&app_path);
    }

    println!();
    println!("✓ FSKitBridge installed successfully");

    // Launch if requested
    if !no_launch {
        println!();
        println!("Launching FSKitBridge.app to register extension...");
        if let Err(e) = launch_bridge() {
            println!("Warning: Failed to launch: {e}");
        } else {
            println!("✓ FSKitBridge launched");
            println!();
            println!("Next steps:");
            println!("  1. Open System Settings: oxfskit-setup open-settings");
            println!("  2. Enable FSKitBridge under File System Extensions");
        }
    }

    Ok(())
}

fn cmd_launch() -> Result<(), Box<dyn std::error::Error>> {
    println!("Launching FSKitBridge.app...");

    let path = launch_bridge()?;
    println!("✓ Launched: {}", path.display());
    println!();
    println!("The FSKit extension should now be registered.");
    println!("Enable it in System Settings → Login Items → File System Extensions");

    Ok(())
}

fn cmd_open_settings() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening System Settings...");

    open_system_settings_extensions()?;
    println!("✓ Opened System Settings");
    println!();
    println!("Navigate to: Login Items & Extensions → File System Extensions");
    println!("Enable the FSKitBridge extension.");

    Ok(())
}

fn cmd_remove_quarantine(path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let app_path = path
        .or_else(find_installation)
        .ok_or("FSKitBridge.app not found. Specify path with --path")?;

    println!("Removing quarantine from: {}", app_path.display());

    remove_quarantine(&app_path)?;
    println!("✓ Quarantine attribute removed");

    Ok(())
}

fn cmd_ping(timeout_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    println!("Pinging FSKitBridge on port {BRIDGE_PORT}...");

    let rt = tokio::runtime::Runtime::new()?;
    let connected = rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            setup::check_bridge_connection(),
        )
        .await
        .unwrap_or(false)
    });

    if connected {
        println!("✓ FSKitBridge is responding");
        Ok(())
    } else {
        println!("✗ FSKitBridge is not responding");
        println!();
        println!("Possible causes:");
        println!("  - FSKitBridge.app is not running");
        println!("  - FSKit extension is not enabled in System Settings");
        println!("  - Extension requires approval after macOS update");
        Err("FSKitBridge not responding".into())
    }
}
