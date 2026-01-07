//! Force lock dialog component
//!
//! Shown when a vault cannot be locked due to open files/processes.
//! Displays blocking processes and offers retry, force lock, or cancel options.

use dioxus::prelude::*;
use oxcrypt_mount::ProcessInfo;

use crate::icons::{Icon, IconColor, IconName, IconSize};

/// Props for the force lock dialog
#[derive(Props, Clone, PartialEq)]
pub struct ForceLockDialogProps {
    /// Name of the vault being locked
    pub vault_name: String,
    /// Error message from the failed lock attempt
    pub error_message: String,
    /// Processes blocking the unmount (from lsof)
    pub processes: Vec<ProcessInfo>,
    /// Called when the user wants to retry normal lock
    pub on_retry: EventHandler<()>,
    /// Called when the user confirms force lock
    pub on_force: EventHandler<()>,
    /// Called when the user cancels
    pub on_cancel: EventHandler<()>,
}

/// Dialog shown when a vault cannot be locked due to busy filesystem
#[component]
pub fn ForceLockDialog(props: ForceLockDialogProps) -> Element {
    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            tabindex: "-1",
            autofocus: true,
            onclick: move |_| props.on_cancel.call(()),
            onkeydown: move |e| {
                if e.key() == Key::Escape {
                    props.on_cancel.call(());
                }
            },

            // Dialog
            div {
                class: "dialog w-[480px]",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "pt-5 px-6",

                    h2 {
                        class: "text-lg font-semibold text-gray-900 dark:text-gray-100",
                        "Cannot Lock Vault"
                    }
                }

                // Content
                div {
                    class: "p-4 px-6",

                    p {
                        class: "text-sm text-gray-600 dark:text-gray-400 leading-relaxed",
                        "The vault \"{props.vault_name}\" cannot be locked because files are in use."
                    }

                    // Process list (if any found)
                    if !props.processes.is_empty() {
                        div {
                            class: "mt-4",

                            h3 {
                                class: "text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-2",
                                "Applications using this vault"
                            }

                            div {
                                class: "bg-gray-50 dark:bg-neutral-800 rounded-lg border border-gray-200 dark:border-neutral-700 max-h-32 overflow-y-auto",

                                ul {
                                    class: "divide-y divide-gray-200 dark:divide-neutral-700",

                                    for proc in props.processes.iter() {
                                        li {
                                            class: "px-3 py-2 text-sm",

                                            span {
                                                class: "font-medium text-gray-900 dark:text-gray-100",
                                                "{proc.name}"
                                            }
                                            span {
                                                class: "text-gray-500 dark:text-gray-400 ml-2",
                                                "(PID {proc.pid})"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Warning box
                    div {
                        class: "alert-warning mt-4",

                        span {
                            class: "icon-container shrink-0",
                            Icon { name: IconName::Warning, size: IconSize(18), color: IconColor::Warning }
                        }

                        p {
                            class: "text-sm leading-normal",
                            "Force locking may cause data loss in applications with unsaved changes."
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
                        "Cancel"
                    }

                    // Retry button
                    button {
                        class: "btn-secondary",
                        onclick: move |_| props.on_retry.call(()),
                        "Retry"
                    }

                    // Force Lock button
                    button {
                        class: "btn-danger",
                        onclick: move |_| props.on_force.call(()),
                        "Force Lock"
                    }
                }
            }
        }
    }
}
