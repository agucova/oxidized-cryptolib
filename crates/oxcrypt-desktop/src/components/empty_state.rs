//! Empty state component shown when no vault is selected

use dioxus::prelude::*;

/// Component displayed when no vault is selected
#[component]
pub fn EmptyState() -> Element {
    rsx! {
        div {
            class: "empty-state",

            h2 {
                class: "empty-state-title",
                "Select a Vault"
            }

            p {
                class: "empty-state-description",
                "Choose a vault from the sidebar to view details and manage it."
            }
        }
    }
}
