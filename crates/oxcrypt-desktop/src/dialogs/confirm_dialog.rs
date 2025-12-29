//! Confirmation dialog component
//!
//! A reusable dialog for confirming destructive or important actions.

use dioxus::prelude::*;

use crate::icons::{Icon, IconColor, IconName, IconSize};

/// Props for the confirmation dialog
#[derive(Props, Clone, PartialEq)]
pub struct ConfirmDialogProps {
    /// Dialog title
    pub title: String,
    /// Main message explaining what will happen
    pub message: String,
    /// Optional warning text (displayed with warning styling)
    #[props(default)]
    pub warning: Option<String>,
    /// Label for the confirm button (e.g., "Remove", "Delete", "Continue")
    #[props(default = "Confirm")]
    pub confirm_label: &'static str,
    /// Label for the cancel button
    #[props(default = "Cancel")]
    pub cancel_label: &'static str,
    /// Whether this is a dangerous action (red confirm button)
    #[props(default = false)]
    pub danger: bool,
    /// Called when the user confirms the action
    pub on_confirm: EventHandler<()>,
    /// Called when the user cancels
    pub on_cancel: EventHandler<()>,
}

/// A reusable confirmation dialog component
#[component]
pub fn ConfirmDialog(props: ConfirmDialogProps) -> Element {
    let confirm_class = if props.danger { "btn-danger" } else { "btn-primary" };

    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            onclick: move |_| props.on_cancel.call(()),

            // Dialog
            div {
                class: "dialog w-[400px]",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "pt-5 px-6",

                    h2 {
                        class: "text-lg font-semibold text-gray-900 dark:text-gray-100",
                        "{props.title}"
                    }
                }

                // Content
                div {
                    class: "p-4 px-6",

                    p {
                        class: "text-sm text-gray-600 dark:text-gray-400 leading-relaxed",
                        "{props.message}"
                    }

                    // Warning box (if provided)
                    if let Some(warning) = &props.warning {
                        div {
                            class: "alert-warning mt-4",

                            span {
                                class: "icon-container shrink-0",
                                Icon { name: IconName::Warning, size: IconSize(18), color: IconColor::Warning }
                            }

                            p {
                                class: "text-sm leading-normal",
                                "{warning}"
                            }
                        }
                    }
                }

                // Footer with buttons
                div {
                    class: "dialog-footer",

                    // Cancel button
                    button {
                        class: "btn-secondary",
                        onclick: move |_| props.on_cancel.call(()),
                        "{props.cancel_label}"
                    }

                    // Confirm button
                    button {
                        class: "{confirm_class}",
                        onclick: move |_| props.on_confirm.call(()),
                        "{props.confirm_label}"
                    }
                }
            }
        }
    }
}
