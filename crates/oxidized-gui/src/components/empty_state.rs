//! Empty state component shown when no vault is selected

use dioxus::prelude::*;

/// Component displayed when no vault is selected
#[component]
pub fn EmptyState() -> Element {
    rsx! {
        div {
            class: "empty-state",
            style: "
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                height: 100%;
                text-align: center;
                color: #666;
            ",

            div {
                style: "font-size: 64px; margin-bottom: 16px; opacity: 0.5;",
                "🔐"
            }

            h2 {
                style: "margin: 0 0 8px 0; font-size: 20px; font-weight: 500; color: #333;",
                "Select a Vault"
            }

            p {
                style: "margin: 0; font-size: 14px; max-width: 280px;",
                "Choose a vault from the sidebar to view its details and manage it."
            }
        }
    }
}
