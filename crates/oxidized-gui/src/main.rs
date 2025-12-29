//! Oxidized Vault - Desktop GUI for Cryptomator vault management
//!
//! A Dioxus-based desktop application for managing Cryptomator vaults with
//! support for multiple filesystem backends (FUSE, FSKit).

#![forbid(unsafe_code)]

mod app;
mod backend;
mod components;
mod dialogs;
mod error;
mod state;
mod tray;

use crossbeam_channel::Receiver;
use std::sync::OnceLock;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use tray::{TrayEvent, TrayManager};

/// Global tray event receiver for the app to poll
static TRAY_RECEIVER: OnceLock<Receiver<TrayEvent>> = OnceLock::new();

/// Get the global tray event receiver
pub fn tray_receiver() -> Option<&'static Receiver<TrayEvent>> {
    TRAY_RECEIVER.get()
}

fn main() {
    // Initialize tracing for logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("oxidized_gui=info".parse().unwrap()))
        .init();

    tracing::info!("Starting Oxidized Vault");

    // Set up signal handler for graceful shutdown (Cmd+Q, Dock quit, etc.)
    if let Err(e) = ctrlc::set_handler(|| backend::cleanup_and_exit()) {
        tracing::warn!("Failed to set signal handler: {}", e);
    }

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

    // Launch the Dioxus desktop application
    dioxus::LaunchBuilder::new()
        .with_cfg(
            dioxus::desktop::Config::new()
                .with_window(
                    dioxus::desktop::WindowBuilder::new()
                        .with_title("Oxidized Vault")
                        .with_inner_size(dioxus::desktop::LogicalSize::new(900.0, 600.0))
                        .with_min_inner_size(dioxus::desktop::LogicalSize::new(600.0, 400.0))
                        .with_resizable(true),
                )
                .with_close_behaviour(dioxus::desktop::WindowCloseBehaviour::WindowHides),
        )
        .launch(app::App);

    // Fallback cleanup if launch() returns normally (shouldn't happen with WindowHides)
    backend::cleanup_and_exit();
}
