//! Sidebar component showing the list of vaults

use dioxus::prelude::*;

use super::{Toolbar, VaultCard};
use crate::state::use_app_state;

/// Sidebar component displaying the list of configured vaults
#[component]
pub fn Sidebar(
    selected_vault_id: Option<String>,
    on_select: EventHandler<String>,
    on_add_vault: EventHandler<()>,
    on_new_vault: EventHandler<()>,
    on_settings: EventHandler<()>,
) -> Element {
    let app_state = use_app_state();
    let vaults = app_state.read().vaults();

    rsx! {
        div {
            class: "sidebar",

            // Header
            div {
                class: "sidebar-header border-b border-gray-200/70 dark:border-neutral-800",
                h1 {
                    class: "text-[15px] font-semibold text-gray-900 dark:text-gray-100",
                    "Oxcrypt Vaults"
                }
            }

            // Vault list
            div {
                class: "flex-1 overflow-y-auto py-2",

                if vaults.is_empty() {
                    // Empty state
                    div {
                        class: "py-8 px-4 text-center",
                        p {
                            class: "text-[13px] text-gray-600 dark:text-gray-400 mb-1",
                            "No vaults configured"
                        }
                        p {
                            class: "text-[11px] text-gray-500 dark:text-gray-500",
                            "Click \"New\" or \"Add\" to get started"
                        }
                    }
                } else {
                    for vault in vaults {
                        VaultCard {
                            key: "{vault.config.id}",
                            vault: vault.clone(),
                            is_selected: selected_vault_id.as_ref() == Some(&vault.config.id),
                            on_click: {
                                let id = vault.config.id.clone();
                                move |()| on_select.call(id.clone())
                            },
                        }
                    }
                }
            }

            // Bottom toolbar
            Toolbar { on_add_vault, on_new_vault, on_settings }
        }
    }
}
