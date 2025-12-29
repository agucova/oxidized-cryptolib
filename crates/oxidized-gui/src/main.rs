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
use std::sync::OnceLock;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
#[cfg(feature = "tokio-console")]
use tracing_subscriber::layer::SubscriberExt;

use menu::MenuBarEvent;
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
