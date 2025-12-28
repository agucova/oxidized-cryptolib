//! Backend selection dialog

use dioxus::prelude::*;

use crate::backend::{mount_manager, BackendInfo, BackendType};

/// Props for the backend selection dialog
#[derive(Props, Clone, PartialEq)]
pub struct BackendDialogProps {
    /// Currently selected backend
    pub current_backend: BackendType,
    /// Called when a backend is selected
    pub on_select: EventHandler<BackendType>,
    /// Called when dialog is cancelled
    pub on_cancel: EventHandler<()>,
}

/// Backend selection dialog modal
#[component]
pub fn BackendDialog(props: BackendDialogProps) -> Element {
    let manager = mount_manager();
    let backends: Vec<BackendInfo> = manager.backend_info();

    let mut selected = use_signal(|| props.current_backend);

    let handle_confirm = {
        let on_select = props.on_select;
        move |_| {
            on_select.call(selected());
        }
    };

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
                    padding: 24px;
                    width: 450px;
                    max-width: 90vw;
                    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
                ",
                onclick: move |e| e.stop_propagation(),

                // Header
                h2 {
                    style: "margin: 0 0 8px 0; font-size: 20px; font-weight: 600; color: #1a1a1a;",
                    "Select Backend"
                }

                p {
                    style: "margin: 0 0 20px 0; font-size: 14px; color: #666;",
                    "Choose which filesystem backend to use for mounting this vault."
                }

                // Backend options
                div {
                    style: "display: flex; flex-direction: column; gap: 8px; margin-bottom: 20px;",

                    for backend in backends.iter() {
                        BackendOption {
                            info: backend.clone(),
                            is_selected: selected() == backend.backend_type,
                            on_click: move |backend_type| {
                                selected.set(backend_type);
                            },
                        }
                    }
                }

                // Buttons
                div {
                    style: "display: flex; gap: 12px; justify-content: flex-end;",

                    button {
                        style: "
                            padding: 10px 20px;
                            background: #f5f5f5;
                            color: #333;
                            border: none;
                            border-radius: 6px;
                            font-size: 14px;
                            cursor: pointer;
                        ",
                        onclick: move |_| props.on_cancel.call(()),
                        "Cancel"
                    }

                    button {
                        style: "
                            padding: 10px 20px;
                            background: #2196f3;
                            color: white;
                            border: none;
                            border-radius: 6px;
                            font-size: 14px;
                            cursor: pointer;
                        ",
                        onclick: handle_confirm,
                        "Save"
                    }
                }
            }
        }
    }
}

/// A single backend option in the selection list
#[component]
fn BackendOption(
    info: BackendInfo,
    is_selected: bool,
    on_click: EventHandler<BackendType>,
) -> Element {
    let is_available = info.available;
    let border_color = if is_selected { "#2196f3" } else { "#ddd" };
    let bg_color = if is_selected { "#e3f2fd" } else if !is_available { "#f5f5f5" } else { "#fff" };
    let opacity = if is_available { "1" } else { "0.6" };
    let cursor = if is_available { "pointer" } else { "not-allowed" };
    let radio_border_color = if is_selected { "#2196f3" } else { "#999" };

    let status_badge = if is_available {
        rsx! {
            span {
                style: "
                    font-size: 11px;
                    padding: 2px 8px;
                    background: #e8f5e9;
                    color: #2e7d32;
                    border-radius: 10px;
                ",
                "Available"
            }
        }
    } else {
        rsx! {
            span {
                style: "
                    font-size: 11px;
                    padding: 2px 8px;
                    background: #fff3e0;
                    color: #e65100;
                    border-radius: 10px;
                ",
                "Unavailable"
            }
        }
    };

    let backend_type = info.backend_type;

    rsx! {
        button {
            style: "
                display: flex;
                flex-direction: column;
                gap: 4px;
                padding: 12px 16px;
                background: {bg_color};
                border: 2px solid {border_color};
                border-radius: 8px;
                text-align: left;
                cursor: {cursor};
                opacity: {opacity};
                transition: border-color 0.15s ease;
            ",
            disabled: !is_available,
            onclick: move |_| {
                if is_available {
                    on_click.call(backend_type);
                }
            },

            // Header row
            div {
                style: "display: flex; align-items: center; justify-content: space-between; width: 100%;",

                div {
                    style: "display: flex; align-items: center; gap: 8px;",

                    // Radio indicator
                    span {
                        style: "
                            width: 16px;
                            height: 16px;
                            border: 2px solid {radio_border_color};
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        ",
                        if is_selected {
                            span {
                                style: "
                                    width: 8px;
                                    height: 8px;
                                    background: #2196f3;
                                    border-radius: 50%;
                                ",
                            }
                        }
                    }

                    span {
                        style: "font-size: 14px; font-weight: 500; color: #1a1a1a;",
                        "{info.name}"
                    }
                }

                {status_badge}
            }

            // Description
            p {
                style: "margin: 4px 0 0 24px; font-size: 12px; color: #666;",
                "{info.description}"
            }

            // Unavailable reason
            if !is_available {
                if let Some(reason) = &info.unavailable_reason {
                    p {
                        style: "margin: 4px 0 0 24px; font-size: 11px; color: #e65100;",
                        "{reason}"
                    }
                }
            }
        }
    }
}
