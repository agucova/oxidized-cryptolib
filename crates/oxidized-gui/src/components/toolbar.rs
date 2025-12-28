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
            class: "toolbar",
            style: "
                display: flex;
                gap: 8px;
                padding: 12px 16px;
                border-top: 1px solid #e0e0e0;
                background: #fafafa;
            ",

            // New vault button (create from scratch)
            button {
                style: "
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    padding: 8px 12px;
                    background: #4caf50;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 500;
                    cursor: pointer;
                ",
                onclick: move |_| on_new_vault.call(()),
                span { "✨" }
                span { "New" }
            }

            // Add existing vault button
            button {
                style: "
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    padding: 8px 12px;
                    background: #2196f3;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 500;
                    cursor: pointer;
                ",
                onclick: move |_| on_add_vault.call(()),
                span { "+" }
                span { "Add" }
            }

            // Settings button
            button {
                style: "
                    padding: 8px 12px;
                    background: transparent;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    font-size: 16px;
                    cursor: pointer;
                ",
                onclick: move |_| on_settings.call(()),
                "⚙️"
            }
        }
    }
}
