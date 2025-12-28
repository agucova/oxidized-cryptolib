//! Vault card component for displaying a single vault in the sidebar

use dioxus::prelude::*;

use crate::state::{ManagedVault, VaultState};

/// A card component displaying a vault's name, path, and status
#[component]
pub fn VaultCard(vault: ManagedVault, is_selected: bool, on_click: EventHandler<()>) -> Element {
    let bg_color = if is_selected { "#e3f2fd" } else { "#ffffff" };
    let border_color = if is_selected { "#2196f3" } else { "transparent" };

    let status_icon = match &vault.state {
        VaultState::Locked => "🔒",
        VaultState::Unlocked => "🔓",
        VaultState::Mounted { .. } => "📂",
    };

    let status_color = match &vault.state {
        VaultState::Locked => "#666",
        VaultState::Unlocked => "#ff9800",
        VaultState::Mounted { .. } => "#4caf50",
    };

    // Truncate path for display
    let display_path = vault
        .config
        .path
        .to_string_lossy()
        .chars()
        .take(30)
        .collect::<String>();
    let display_path = if vault.config.path.to_string_lossy().len() > 30 {
        format!("...{}", display_path)
    } else {
        display_path
    };

    rsx! {
        div {
            class: "vault-card",
            style: "
                padding: 12px;
                margin: 4px 0;
                background: {bg_color};
                border: 2px solid {border_color};
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.15s ease;
            ",
            onclick: move |_| on_click.call(()),

            // Header with icon and name
            div {
                style: "display: flex; align-items: center; gap: 8px; margin-bottom: 4px;",

                span {
                    style: "font-size: 16px;",
                    "{status_icon}"
                }

                span {
                    style: "font-size: 14px; font-weight: 500; color: #1a1a1a; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;",
                    "{vault.config.name}"
                }
            }

            // Path
            div {
                style: "font-size: 11px; color: #666; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;",
                "{display_path}"
            }

            // Status indicator
            if vault.state.is_mounted() {
                if let Some(mountpoint) = vault.state.mountpoint() {
                    div {
                        style: "font-size: 10px; color: {status_color}; margin-top: 4px;",
                        "Mounted at {mountpoint.display()}"
                    }
                }
            }
        }
    }
}
