//! Application state management
//!
//! Handles vault configurations, persistence, and runtime state.

pub mod config;
mod vault_manager;

pub use config::{BackendType, ThemePreference, VaultConfig};
pub use vault_manager::{AppState, ManagedVault, VaultState};

use dioxus::prelude::*;

/// Hook to access the application state
pub fn use_app_state() -> Signal<AppState> {
    use_context::<Signal<AppState>>()
}
