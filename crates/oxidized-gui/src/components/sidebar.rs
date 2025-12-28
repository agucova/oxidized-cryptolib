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
            style: "width: 280px; min-width: 280px; background: #ffffff; border-right: 1px solid #e0e0e0; display: flex; flex-direction: column;",

            // Header
            div {
                class: "sidebar-header",
                style: "padding: 16px; border-bottom: 1px solid #e0e0e0;",
                h1 {
                    style: "margin: 0; font-size: 18px; font-weight: 600; color: #1a1a1a;",
                    "Vaults"
                }
            }

            // Vault list
            div {
                class: "vault-list",
                style: "flex: 1; overflow-y: auto; padding: 8px;",

                if vaults.is_empty() {
                    div {
                        style: "padding: 24px 16px; text-align: center; color: #666;",
                        p {
                            style: "margin: 0 0 8px 0; font-size: 14px;",
                            "No vaults configured"
                        }
                        p {
                            style: "margin: 0; font-size: 12px; color: #999;",
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
