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
            class: "w-[280px] min-w-[280px] bg-white dark:bg-neutral-900 border-r border-gray-200 dark:border-neutral-700 flex flex-col",

            // Header
            div {
                class: "p-4 border-b border-gray-100 dark:border-neutral-800",
                h1 {
                    class: "text-lg font-semibold text-gray-900 dark:text-gray-100",
                    "Vaults"
                }
            }

            // Vault list
            div {
                class: "flex-1 overflow-y-auto p-2",

                if vaults.is_empty() {
                    div {
                        class: "py-6 px-4 text-center",
                        p {
                            class: "mb-2 text-sm text-gray-600 dark:text-gray-400",
                            "No vaults configured"
                        }
                        p {
                            class: "text-xs text-gray-500",
                            "Click + to add a vault"
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
                                move |_| on_select.call(id.clone())
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
