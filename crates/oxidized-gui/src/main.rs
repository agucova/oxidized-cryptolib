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

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() {
    // Initialize tracing for logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("oxidized_gui=info".parse().unwrap()))
        .init();

    tracing::info!("Starting Oxidized Vault");

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
}
