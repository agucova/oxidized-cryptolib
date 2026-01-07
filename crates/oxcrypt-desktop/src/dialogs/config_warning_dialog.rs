//! Config warning dialog component
//!
//! Displays a warning when the configuration file was corrupted or couldn't
//! be loaded. Informs the user that a backup was created and they may need
//! to re-add their vaults.

use dioxus::prelude::*;

use crate::icons::{Icon, IconColor, IconName, IconSize};

/// Props for the config warning dialog
#[derive(Props, Clone, PartialEq)]
pub struct ConfigWarningDialogProps {
    /// The warning message to display
    pub message: String,
    /// Called when the user dismisses the dialog
    pub on_dismiss: EventHandler<()>,
}

/// A dialog for warning users about config file issues
#[component]
pub fn ConfigWarningDialog(props: ConfigWarningDialogProps) -> Element {
    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            onclick: move |_| { props.on_dismiss.call(()) },

            // Dialog
            div {
                class: "dialog w-[500px]",
                onclick: move |e| e.stop_propagation(),

                // Header with warning icon
                div {
                    class: "p-6 pb-0 flex items-start gap-4",

                    // Warning icon
                    div {
                        class: "w-12 h-12 rounded-full bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center shrink-0",
                        span {
                            class: "icon-container",
                            Icon { name: IconName::Warning, size: IconSize(28), color: IconColor::Warning }
                        }
                    }

                    div {
                        class: "flex-1",
                        h2 {
                            class: "mb-1 text-lg font-semibold text-gray-900 dark:text-gray-100",
                            "Configuration Issue Detected"
                        }
                        p {
                            class: "text-sm text-gray-600 dark:text-gray-400 leading-relaxed",
                            "There was a problem loading your configuration file."
                        }
                    }
                }

                // Content
                div {
                    class: "p-6 pt-4",

                    // Message box with scroll for long paths
                    div {
                        class: "p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg",

                        pre {
                            class: "text-sm text-amber-800 dark:text-amber-200 whitespace-pre-wrap break-words font-mono max-h-[200px] overflow-y-auto",
                            "{props.message}"
                        }
                    }

                    // Help text
                    div {
                        class: "mt-4 flex items-start gap-2",

                        span {
                            class: "icon-container shrink-0 mt-0.5",
                            Icon { name: IconName::InfoCircle, size: IconSize(16), color: IconColor::Accent }
                        }

                        p {
                            class: "text-sm text-gray-600 dark:text-gray-400 leading-relaxed",
                            "If you believe this was a one-time issue (e.g., disk error), you can manually restore "
                            "the backup file by renaming it back to "
                            code {
                                class: "px-1 py-0.5 bg-gray-100 dark:bg-neutral-700 rounded text-xs",
                                "config.json"
                            }
                            "."
                        }
                    }
                }

                // Footer
                div {
                    class: "dialog-footer",

                    button {
                        class: "btn-primary",
                        onclick: move |_| { props.on_dismiss.call(()) },
                        "I Understand"
                    }
                }
            }
        }
    }
}
