//! Bottom toolbar component with add/settings buttons

use dioxus::prelude::*;

/// Bottom toolbar with vault management buttons
#[component]
pub fn Toolbar(
    on_add_vault: EventHandler<()>,
    on_new_vault: EventHandler<()>,
    on_settings: EventHandler<()>,
) -> Element {
    rsx! {
        div {
            class: "flex gap-2 py-3 px-4 border-t border-gray-100 dark:border-neutral-800 bg-gray-50 dark:bg-neutral-900",

            // New vault button (create from scratch)
            button {
                class: "btn-success btn-sm",
                onclick: move |_| on_new_vault.call(()),
                span { "✨" }
                span { "New" }
            }

            // Add existing vault button
            button {
                class: "btn-primary btn-sm",
                onclick: move |_| on_add_vault.call(()),
                span { "+" }
                span { "Add" }
            }

            // Settings button
            button {
                class: "btn-secondary btn-sm px-2.5 py-1.5",
                onclick: move |_| on_settings.call(()),
                "⚙️"
            }
        }
    }
}
