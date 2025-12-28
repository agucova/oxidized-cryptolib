//! Confirmation dialog component
//!
//! A reusable dialog for confirming destructive or important actions.

use dioxus::prelude::*;

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
    let confirm_bg = if props.danger { "#dc2626" } else { "#2196f3" };

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
            onclick: move |_| props.on_cancel.call(()),

            // Dialog
            div {
                style: "
                    background: white;
                    border-radius: 12px;
                    width: 400px;
                    max-width: 90vw;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
                    overflow: hidden;
                ",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    style: "padding: 20px 24px 0 24px;",

                    h2 {
                        style: "margin: 0; font-size: 18px; font-weight: 600; color: #1a1a1a;",
                        "{props.title}"
                    }
                }

                // Content
                div {
                    style: "padding: 16px 24px;",

                    p {
                        style: "margin: 0; font-size: 14px; color: #555; line-height: 1.5;",
                        "{props.message}"
                    }

                    // Warning box (if provided)
                    if let Some(warning) = &props.warning {
                        div {
                            style: "
                                margin-top: 16px;
                                padding: 12px 16px;
                                background: #fef3c7;
                                border: 1px solid #f59e0b;
                                border-radius: 8px;
                                display: flex;
                                gap: 10px;
                                align-items: flex-start;
                            ",

                            span {
                                style: "font-size: 16px; flex-shrink: 0;",
                                "⚠️"
                            }

                            p {
                                style: "margin: 0; font-size: 13px; color: #92400e; line-height: 1.4;",
                                "{warning}"
                            }
                        }
                    }
                }

                // Footer with buttons
                div {
                    style: "
                        padding: 16px 24px;
                        background: #f9fafb;
                        display: flex;
                        justify-content: flex-end;
                        gap: 12px;
                    ",

                    // Cancel button
                    button {
                        style: "
                            padding: 10px 20px;
                            background: white;
                            color: #374151;
                            border: 1px solid #d1d5db;
                            border-radius: 6px;
                            font-size: 14px;
                            font-weight: 500;
                            cursor: pointer;
                        ",
                        onclick: move |_| props.on_cancel.call(()),
                        "{props.cancel_label}"
                    }

                    // Confirm button
                    button {
                        style: "
                            padding: 10px 20px;
                            background: {confirm_bg};
                            color: white;
                            border: none;
                            border-radius: 6px;
                            font-size: 14px;
                            font-weight: 500;
                            cursor: pointer;
                        ",
                        onclick: move |_| props.on_confirm.call(()),
                        "{props.confirm_label}"
                    }
                }
            }
        }
    }
}
