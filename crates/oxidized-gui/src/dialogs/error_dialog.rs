//! Error dialog component
//!
//! Displays user-friendly error messages with suggestions for resolution.

use dioxus::prelude::*;

use crate::error::UserFacingError;
use crate::icons::{Icon, IconColor, IconName, IconSize};

/// Props for the error dialog
#[derive(Props, Clone, PartialEq)]
pub struct ErrorDialogProps {
    /// The error to display
    pub error: UserFacingError,
    /// Called when the user dismisses the dialog
    pub on_dismiss: EventHandler<()>,
}

/// A dialog for displaying user-friendly error messages
#[component]
pub fn ErrorDialog(props: ErrorDialogProps) -> Element {
    let mut show_technical = use_signal(|| false);
    let has_technical = props.error.technical_details.is_some();

    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            onclick: move |_| props.on_dismiss.call(()),

            // Dialog
            div {
                class: "dialog w-[420px]",
                onclick: move |e| e.stop_propagation(),

                // Header with error icon
                div {
                    class: "p-6 pb-0 flex items-start gap-4",

                    // Error icon
                    div {
                        class: "w-12 h-12 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center shrink-0",
                        span {
                            class: "icon-container",
                            Icon { name: IconName::XCircle, size: IconSize(28), color: IconColor::Danger }
                        }
                    }

                    div {
                        class: "flex-1",
                        h2 {
                            class: "mb-1 text-lg font-semibold text-gray-900 dark:text-gray-100",
                            "{props.error.title}"
                        }
                        p {
                            class: "text-sm text-gray-600 dark:text-gray-400 leading-relaxed",
                            "{props.error.message}"
                        }
                    }
                }

                // Content
                div {
                    class: "p-4 px-6",

                    // Suggestion (if provided)
                    if let Some(suggestion) = &props.error.suggestion {
                        div {
                            class: "alert-info",

                            span {
                                class: "icon-container shrink-0",
                                Icon { name: IconName::InfoCircle, size: IconSize(18), color: IconColor::Accent }
                            }

                            p {
                                class: "text-sm leading-normal",
                                "{suggestion}"
                            }
                        }
                    }

                    // Technical details (expandable)
                    if has_technical {
                        div {
                            class: "mt-4",

                            button {
                                class: "p-0 text-sm flex items-center gap-1 bg-transparent border-none cursor-pointer text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200",
                                onclick: move |_| show_technical.set(!show_technical()),

                                {
                                    let rotation = if show_technical() { "rotate-90" } else { "" };
                                    rsx! {
                                        span {
                                            class: "inline-block transition-transform duration-150 {rotation}",
                                            "▶"
                                        }
                                    }
                                }
                                span { "Technical Details" }
                            }

                            if show_technical() {
                                if let Some(details) = &props.error.technical_details {
                                    pre {
                                        class: "mt-2 p-3 bg-gray-100 dark:bg-neutral-700 rounded-md text-xs font-mono text-gray-600 dark:text-gray-400 whitespace-pre-wrap break-words max-h-[150px] overflow-y-auto",
                                        "{details}"
                                    }
                                }
                            }
                        }
                    }
                }

                // Footer
                div {
                    class: "dialog-footer",

                    button {
                        class: "btn-primary",
                        onclick: move |_| props.on_dismiss.call(()),
                        "OK"
                    }
                }
            }
        }
    }
}
