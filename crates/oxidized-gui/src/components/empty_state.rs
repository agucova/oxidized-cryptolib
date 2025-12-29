//! Empty state component shown when no vault is selected

use dioxus::prelude::*;

/// Component displayed when no vault is selected
#[component]
pub fn EmptyState() -> Element {
    rsx! {
        div {
            class: "flex flex-col items-center justify-center h-full text-center p-8",

            // Icon container with subtle background
            div {
                class: "w-24 h-24 flex items-center justify-center bg-gray-100 dark:bg-neutral-700 rounded-full mb-6",
                span {
                    class: "text-5xl opacity-80",
                    "🔐"
                }
            }

            h2 {
                class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                "Select a Vault"
            }

            p {
                class: "text-sm text-gray-600 dark:text-gray-400 max-w-[300px] leading-relaxed",
                "Choose a vault from the sidebar to view its details and manage it."
            }
        }
    }
}
