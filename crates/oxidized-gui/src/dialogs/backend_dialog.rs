//! Backend selection dialog

use dioxus::prelude::*;

use crate::backend::{mount_manager, BackendInfo, BackendType};

/// Props for the backend selection dialog
#[derive(Props, Clone, PartialEq)]
pub struct BackendDialogProps {
    /// Currently selected backend
    pub current_backend: BackendType,
    /// Whether the vault is currently mounted
    pub is_mounted: bool,
    /// Called when a backend is selected (save only)
    pub on_select: EventHandler<BackendType>,
    /// Called when user wants to unmount and apply immediately
    pub on_unmount_and_apply: EventHandler<BackendType>,
    /// Called when dialog is cancelled
    pub on_cancel: EventHandler<()>,
}

/// Backend selection dialog modal
#[component]
pub fn BackendDialog(props: BackendDialogProps) -> Element {
    let manager = mount_manager();
    let backends: Vec<BackendInfo> = manager.backend_info();

    let mut selected = use_signal(|| props.current_backend);

    let is_mounted = props.is_mounted;

    let handle_confirm = {
        let on_select = props.on_select;
        move |_| {
            on_select.call(selected());
        }
    };

    let handle_unmount_and_apply = {
        let on_unmount_and_apply = props.on_unmount_and_apply;
        move |_| {
            on_unmount_and_apply.call(selected());
        }
    };

    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            onclick: move |_| props.on_cancel.call(()),

            // Dialog
            div {
                class: "dialog w-[450px]",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "dialog-body",

                    h2 {
                        class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                        "Select Backend"
                    }

                    p {
                        class: "mb-4 text-sm text-gray-600 dark:text-gray-400",
                        "Choose which filesystem backend to use for mounting this vault."
                    }

                    // Mount state alert
                    if is_mounted {
                        div {
                            class: "alert-warning mb-4",
                            "This vault is currently mounted. The new backend will be used next time you unlock this vault."
                        }
                    } else {
                        div {
                            class: "alert-info mb-4",
                            "Change takes effect next time you unlock this vault."
                        }
                    }

                    // Backend options
                    div {
                        class: "flex flex-col gap-2",

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
                }

                // Buttons
                div {
                    class: "dialog-footer",

                    if is_mounted {
                        button {
                            class: "btn-secondary",
                            onclick: handle_unmount_and_apply,
                            "Unmount & Apply"
                        }
                    }

                    button {
                        class: "btn-secondary",
                        onclick: move |_| props.on_cancel.call(()),
                        "Cancel"
                    }

                    button {
                        class: "btn-primary",
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

    let button_class = match (is_selected, is_available) {
        (true, _) => "flex flex-col gap-1 p-3 px-4 bg-blue-50 dark:bg-blue-900/20 border-2 border-blue-500 rounded-lg text-left cursor-pointer transition-colors w-full",
        (false, true) => "flex flex-col gap-1 p-3 px-4 bg-white dark:bg-neutral-800 border-2 border-gray-200 dark:border-neutral-600 rounded-lg text-left cursor-pointer transition-colors w-full hover:border-gray-300 dark:hover:border-neutral-500",
        (false, false) => "flex flex-col gap-1 p-3 px-4 bg-gray-100 dark:bg-neutral-700 border-2 border-gray-200 dark:border-neutral-600 rounded-lg text-left cursor-not-allowed opacity-60 w-full",
    };

    let radio_class = if is_selected {
        "w-4 h-4 border-2 border-blue-500 rounded-full flex items-center justify-center"
    } else {
        "w-4 h-4 border-2 border-gray-400 dark:border-neutral-500 rounded-full flex items-center justify-center"
    };

    let status_badge = if is_available {
        rsx! {
            span {
                class: "badge badge-success",
                "Available"
            }
        }
    } else {
        rsx! {
            span {
                class: "badge badge-warning",
                "Unavailable"
            }
        }
    };

    let backend_type = info.backend_type;

    rsx! {
        button {
            class: button_class,
            disabled: !is_available,
            onclick: move |_| {
                if is_available {
                    on_click.call(backend_type);
                }
            },

            // Header row
            div {
                class: "flex items-center justify-between w-full",

                div {
                    class: "flex items-center gap-2",

                    // Radio indicator
                    span {
                        class: radio_class,
                        if is_selected {
                            span {
                                class: "w-2 h-2 bg-blue-500 rounded-full",
                            }
                        }
                    }

                    span {
                        class: "text-sm font-medium text-gray-900 dark:text-gray-100",
                        "{info.name}"
                    }
                }

                {status_badge}
            }

            // Description
            p {
                class: "mt-1 ml-6 text-sm text-gray-600 dark:text-gray-400",
                "{info.description}"
            }

            // Unavailable reason
            if !is_available {
                if let Some(reason) = &info.unavailable_reason {
                    p {
                        class: "mt-1 ml-6 text-xs text-amber-600 dark:text-amber-400",
                        "{reason}"
                    }
                }
            }
        }
    }
}
