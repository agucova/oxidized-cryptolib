//! Main application component and layout

use dioxus::prelude::*;

use crate::components::{EmptyState, Sidebar, VaultDetail};
use crate::dialogs::{AddVaultDialog, CreateVaultDialog};
use crate::state::{use_app_state, AppState, VaultConfig};

#[cfg(all(target_os = "macos", feature = "fskit"))]
use crate::dialogs::FSKitSetupDialog;

/// Root application component
#[component]
pub fn App() -> Element {
    // Initialize application state
    let _app_state = use_context_provider(|| Signal::new(AppState::load()));
    let mut app_state = use_app_state();
    let mut selected_vault = use_signal(|| None::<String>);
    let mut show_add_vault_dialog = use_signal(|| false);
    let mut show_create_vault_dialog = use_signal(|| false);

    rsx! {
        // Main two-panel layout
        div {
            class: "app-container",
            style: "display: flex; height: 100vh; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;",

            // Left sidebar with vault list
            Sidebar {
                selected_vault_id: selected_vault(),
                on_select: move |id: String| selected_vault.set(Some(id)),
                on_add_vault: move |_| show_add_vault_dialog.set(true),
                on_new_vault: move |_| show_create_vault_dialog.set(true),
            }

            // Right panel with vault details or empty state
            div {
                class: "detail-panel",
                style: "flex: 1; background: #f8f9fa; padding: 24px; overflow-y: auto;",

                if let Some(vault_id) = selected_vault() {
                    VaultDetail { vault_id }
                } else {
                    EmptyState {}
                }
            }
        }

        // Add existing vault dialog
        if show_add_vault_dialog() {
            AddVaultDialog {
                on_complete: move |_| show_add_vault_dialog.set(false),
                on_cancel: move |_| show_add_vault_dialog.set(false),
            }
        }

        // Create new vault wizard
        if show_create_vault_dialog() {
            CreateVaultDialog {
                on_complete: move |path: std::path::PathBuf| {
                    // Add the newly created vault to state
                    let name = path
                        .file_name()
                        .map(|n: &std::ffi::OsStr| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "New Vault".to_string());
                    let config = VaultConfig::new(name, path);
                    let id = config.id.clone();
                    app_state.write().add_vault(config);
                    selected_vault.set(Some(id));
                    show_create_vault_dialog.set(false);
                },
                on_cancel: move |_| show_create_vault_dialog.set(false),
            }
        }

        // FSKit setup wizard (macOS only, conditionally compiled)
        FSKitSetupWrapper {}
    }
}

/// Wrapper component for FSKit setup dialog
///
/// This is a separate component so we can use #[cfg] attributes properly
/// (rsx! macro doesn't support inline #[cfg]).
#[cfg(all(target_os = "macos", feature = "fskit"))]
#[component]
fn FSKitSetupWrapper() -> Element {
    let mut app_state = use_app_state();
    let mut show_fskit_setup = use_signal(|| false);

    // Check FSKit status on startup
    let config_dismissed = app_state.read().config.fskit_setup_dismissed;
    use_effect(move || {
        if config_dismissed {
            return;
        }
        spawn(async move {
            use oxidized_fskit::setup::{get_status, BridgeStatus};
            let status = get_status().await;
            // Show dialog if FSKit needs setup (but is supported)
            if matches!(
                status,
                BridgeStatus::NotInstalled
                    | BridgeStatus::Quarantined
                    | BridgeStatus::ExtensionDisabled
            ) {
                show_fskit_setup.set(true);
            }
        });
    });

    if show_fskit_setup() {
        rsx! {
            FSKitSetupDialog {
                on_complete: move |_| {
                    show_fskit_setup.set(false);
                },
                on_dismiss: move |_| {
                    // Mark as dismissed so we don't show again
                    app_state.write().config.fskit_setup_dismissed = true;
                    let _ = app_state.read().save();
                    show_fskit_setup.set(false);
                },
            }
        }
    } else {
        rsx! {}
    }
}

/// No-op wrapper for non-macOS or non-fskit builds
#[cfg(not(all(target_os = "macos", feature = "fskit")))]
#[component]
fn FSKitSetupWrapper() -> Element {
    rsx! {}
}
