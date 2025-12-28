//! Error dialog component
//!
//! Displays user-friendly error messages with suggestions for resolution.

use dioxus::prelude::*;

use crate::error::UserFacingError;

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
            style: "
                position: fixed;
                inset: 0;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000;
            ",
            onclick: move |_| props.on_dismiss.call(()),

            // Dialog
            div {
                style: "
                    background: white;
                    border-radius: 12px;
                    width: 420px;
                    max-width: 90vw;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
                    overflow: hidden;
                ",
                onclick: move |e| e.stop_propagation(),

                // Header with error icon
                div {
                    style: "
                        padding: 24px 24px 0 24px;
                        display: flex;
                        align-items: flex-start;
                        gap: 16px;
                    ",

                    // Error icon
                    div {
                        style: "
                            width: 48px;
                            height: 48px;
                            border-radius: 50%;
                            background: #fef2f2;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            flex-shrink: 0;
                        ",
                        span {
                            style: "font-size: 24px;",
                            "❌"
                        }
                    }

                    div {
                        style: "flex: 1;",
                        h2 {
                            style: "margin: 0 0 4px 0; font-size: 18px; font-weight: 600; color: #1a1a1a;",
                            "{props.error.title}"
                        }
                        p {
                            style: "margin: 0; font-size: 14px; color: #555; line-height: 1.5;",
                            "{props.error.message}"
                        }
                    }
                }

                // Content
                div {
                    style: "padding: 16px 24px;",

                    // Suggestion (if provided)
                    if let Some(suggestion) = &props.error.suggestion {
                        div {
                            style: "
                                padding: 12px 16px;
                                background: #eff6ff;
                                border: 1px solid #3b82f6;
                                border-radius: 8px;
                                display: flex;
                                gap: 10px;
                                align-items: flex-start;
                            ",

                            span {
                                style: "font-size: 16px; flex-shrink: 0;",
                                "💡"
                            }

                            p {
                                style: "margin: 0; font-size: 13px; color: #1e40af; line-height: 1.4;",
                                "{suggestion}"
                            }
                        }
                    }

                    // Technical details (expandable)
                    if has_technical {
                        div {
                            style: "margin-top: 16px;",

                            button {
                                style: "
                                    background: none;
                                    border: none;
                                    padding: 0;
                                    color: #6b7280;
                                    font-size: 13px;
                                    cursor: pointer;
                                    display: flex;
                                    align-items: center;
                                    gap: 4px;
                                ",
                                onclick: move |_| show_technical.set(!show_technical()),

                                {
                                    let rotation = if show_technical() { "90deg" } else { "0deg" };
                                    rsx! {
                                        span {
                                            style: "display: inline-block; transition: transform 0.15s ease; transform: rotate({rotation});",
                                            "▶"
                                        }
                                    }
                                }
                                span { "Technical Details" }
                            }

                            if show_technical() {
                                if let Some(details) = &props.error.technical_details {
                                    pre {
                                        style: "
                                            margin: 8px 0 0 0;
                                            padding: 12px;
                                            background: #f3f4f6;
                                            border-radius: 6px;
                                            font-size: 12px;
                                            font-family: ui-monospace, monospace;
                                            color: #374151;
                                            white-space: pre-wrap;
                                            word-break: break-word;
                                            max-height: 150px;
                                            overflow-y: auto;
                                        ",
                                        "{details}"
                                    }
                                }
                            }
                        }
                    }
                }

                // Footer
                div {
                    style: "
                        padding: 16px 24px;
                        background: #f9fafb;
                        display: flex;
                        justify-content: flex-end;
                    ",

                    button {
                        style: "
                            padding: 10px 24px;
                            background: #2196f3;
                            color: white;
                            border: none;
                            border-radius: 6px;
                            font-size: 14px;
                            font-weight: 500;
                            cursor: pointer;
                        ",
                        onclick: move |_| props.on_dismiss.call(()),
                        "OK"
                    }
                }
            }
        }
    }
}
