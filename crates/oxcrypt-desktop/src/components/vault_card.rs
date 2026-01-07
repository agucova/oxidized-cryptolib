//! Vault card component for displaying a single vault in the sidebar

use dioxus::prelude::*;

use crate::icons::{Icon, IconColor, IconName, IconSize};
use crate::state::ManagedVault;

/// A card component displaying a vault's name and status
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
    let icon_color = if is_mounted {
        IconColor::Success
    } else {
        IconColor::Secondary
    };

    // Backend display name
    let backend_name = vault.config.preferred_backend.display_name();

    // Status text
    let status_text = if is_mounted {
        "Mounted"
    } else {
        backend_name
    };

    rsx! {
        div {
            class: "{card_class}",
            onclick: move |_| { on_click.call(()); },

            // Icon
            div {
                class: "{icon_class}",
                span {
                class: "icon-container w-full h-full",
                    Icon { name: icon_name, size: IconSize(20), color: icon_color }
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

                // Status/Backend
                p {
                    class: "text-[11px] text-gray-500 dark:text-gray-400 mt-0.5",
                    "{status_text}"
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
