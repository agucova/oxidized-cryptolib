//! Bottom toolbar component with add/settings buttons

use dioxus::prelude::*;

use crate::icons::{Icon, IconName, IconSize};

/// Bottom toolbar with vault management buttons
#[component]
pub fn Toolbar(
    on_add_vault: EventHandler<()>,
    on_new_vault: EventHandler<()>,
    on_settings: EventHandler<()>,
) -> Element {
    rsx! {
        div {
            class: "sidebar-toolbar",

            // New vault button (create from scratch)
            button {
                class: "btn-primary btn-sm",
                onclick: move |_| on_new_vault.call(()),
                span {
                    class: "icon-container",
                    Icon { name: IconName::Plus, size: IconSize(14) }
                }
                span { "New" }
            }

            // Add existing vault button
            button {
                class: "btn-secondary btn-sm",
                onclick: move |_| on_add_vault.call(()),
                span { "Add" }
            }

            // Spacer
            div { class: "flex-1" }

            // Settings button
            button {
                class: "btn-ghost btn-icon btn-sm",
                onclick: move |_| on_settings.call(()),
                title: "Settings",
                span {
                    class: "icon-container w-full h-full",
                    Icon { name: IconName::Gear, size: IconSize(16) }
                }
            }
        }
    }
}
