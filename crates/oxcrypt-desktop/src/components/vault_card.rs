//! Vault card component for displaying a single vault in the sidebar

use dioxus::prelude::*;

use crate::icons::{Icon, IconName, IconSize};
use crate::state::ManagedVault;

/// A card component displaying a vault's name, path, and status
#[component]
pub fn VaultCard(vault: ManagedVault, is_selected: bool, on_click: EventHandler<()>) -> Element {
    let is_mounted = vault.state.is_mounted();

    // Card container classes using new design system
    let card_class = if is_selected {
        "vault-card vault-card-selected"
    } else {
        "vault-card"
    };

    // Icon container classes
    let icon_class = if is_mounted {
        "vault-icon vault-icon-mounted"
    } else {
        "vault-icon vault-icon-locked"
    };

    // Status icon
    let icon_name = if is_mounted {
        IconName::LockOpen
    } else {
        IconName::Lock
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

            // Icon
            div {
                class: "{icon_class}",
                span {
                    class: "icon-container w-full h-full",
                    Icon { name: icon_name, size: IconSize(20) }
                }
            }

            // Content
            div {
                class: "flex-1 min-w-0",

                // Name
                p {
                    class: "text-[13px] font-medium text-gray-900 dark:text-gray-100 truncate leading-snug",
                    "{vault.config.name}"
                }

                // Path
                p {
                    class: "text-[11px] text-gray-500 dark:text-gray-400 truncate mt-0.5",
                    "{display_path}"
                }
            }

            // Mounted indicator dot (pulsing)
            if is_mounted {
                span {
                    class: "vault-mounted-dot"
                }
            }
        }
    }
}
