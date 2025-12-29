//! Vault card component for displaying a single vault in the sidebar

use dioxus::prelude::*;

use crate::state::{ManagedVault, VaultState};

/// A card component displaying a vault's name, path, and status
#[component]
pub fn VaultCard(vault: ManagedVault, is_selected: bool, on_click: EventHandler<()>) -> Element {
    let card_class = if is_selected {
        "p-3 my-1 rounded-lg cursor-pointer transition-all bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800"
    } else {
        "p-3 my-1 rounded-lg cursor-pointer transition-all bg-white dark:bg-neutral-800 border border-transparent hover:bg-gray-50 dark:hover:bg-neutral-700"
    };

    let status_icon_class = match &vault.state {
        VaultState::Locked => "inline-flex items-center justify-center w-7 h-7 text-sm bg-gray-100 dark:bg-neutral-700 rounded-md",
        VaultState::Mounted { .. } => "inline-flex items-center justify-center w-7 h-7 text-sm bg-green-100 dark:bg-green-900/30 rounded-md",
    };

    let status_icon = match &vault.state {
        VaultState::Locked => "🔒",
        VaultState::Mounted { .. } => "📂",
    };

    // Truncate path for display, using ~/ for home directory
    let path_str = vault.config.path.to_string_lossy();
    let display_path = if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if path_str.starts_with(home_str.as_ref()) {
            format!("~{}", &path_str[home_str.len()..])
        } else {
            path_str.to_string()
        }
    } else {
        path_str.to_string()
    };
    let display_path = if display_path.len() > 35 {
        format!("...{}", &display_path[display_path.len() - 32..])
    } else {
        display_path
    };

    rsx! {
        div {
            class: "{card_class}",
            onclick: move |_| on_click.call(()),

            // Header with icon and name
            div {
                class: "flex items-center gap-2 mb-1",

                // Status icon with background
                span {
                    class: "{status_icon_class}",
                    "{status_icon}"
                }

                span {
                    class: "text-sm font-medium text-gray-900 dark:text-gray-100 flex-1 overflow-hidden text-ellipsis whitespace-nowrap",
                    "{vault.config.name}"
                }
            }

            // Path
            div {
                class: "text-xs text-gray-500 dark:text-gray-500 overflow-hidden text-ellipsis whitespace-nowrap ml-9",
                "{display_path}"
            }

            // Status indicator for mounted vaults
            if vault.state.is_mounted() {
                if let Some(_mountpoint) = vault.state.mountpoint() {
                    div {
                        class: "text-xs text-green-600 dark:text-green-400 mt-2 ml-9 flex items-center gap-1",
                        span { class: "w-1.5 h-1.5 bg-green-500 rounded-full" }
                        "Mounted"
                    }
                }
            }
        }
    }
}
