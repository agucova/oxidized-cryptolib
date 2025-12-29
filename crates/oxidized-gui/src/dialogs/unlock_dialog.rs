//! Unlock dialog for entering vault password

use dioxus::prelude::*;

/// State for the unlock dialog
#[derive(Clone, PartialEq)]
#[derive(Default)]
pub enum UnlockState {
    /// Waiting for user input
    #[default]
    Idle,
    /// Currently unlocking
    Unlocking,
    /// Unlock failed with error message
    Error(String),
}

/// Props for the unlock dialog
#[derive(Props, Clone, PartialEq)]
pub struct UnlockDialogProps {
    /// Vault name to display
    pub vault_name: String,
    /// Called when unlock succeeds with the password
    pub on_unlock: EventHandler<String>,
    /// Called when dialog is cancelled
    pub on_cancel: EventHandler<()>,
    /// Current state of the unlock process
    #[props(default)]
    pub state: UnlockState,
}


/// Password unlock dialog modal
#[component]
pub fn UnlockDialog(props: UnlockDialogProps) -> Element {
    let mut password = use_signal(String::new);
    let mut show_password = use_signal(|| false);

    let is_unlocking = matches!(props.state, UnlockState::Unlocking);
    let error_message = match &props.state {
        UnlockState::Error(msg) => Some(msg.clone()),
        _ => None,
    };

    let handle_submit = {
        let on_unlock = props.on_unlock;
        move |_| {
            let pw = password();
            if !pw.is_empty() {
                on_unlock.call(pw);
            }
        }
    };

    let handle_keydown = {
        let on_unlock = props.on_unlock;
        move |e: KeyboardEvent| {
            if e.key() == Key::Enter {
                let pw = password();
                if !pw.is_empty() {
                    on_unlock.call(pw);
                }
            }
        }
    };

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
                    class: "dialog-body",

                    h2 {
                        class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                        "Unlock Vault"
                    }

                    p {
                        class: "mb-5 text-sm text-gray-600 dark:text-gray-400",
                        "Enter the password for \"{props.vault_name}\""
                    }

                    // Password input
                    div {
                        class: "mb-4",

                        div {
                            class: "input-group",

                            input {
                                r#type: if show_password() { "text" } else { "password" },
                                class: if error_message.is_some() { "input input-error pr-11" } else { "input pr-11" },
                                placeholder: "Password",
                                disabled: is_unlocking,
                                value: "{password}",
                                oninput: move |e| password.set(e.value()),
                                onkeydown: handle_keydown,
                                autofocus: true,
                            }

                            // Show/hide password button
                            button {
                                r#type: "button",
                                class: "input-icon bg-transparent border-none cursor-pointer text-base p-1",
                                onclick: move |_| show_password.set(!show_password()),
                                if show_password() { "🙈" } else { "👁️" }
                            }
                        }
                    }

                    // Error message
                    if let Some(ref error) = error_message {
                        div {
                            class: "alert-danger mb-4",
                            "{error}"
                        }
                    }

                    // Buttons
                    div {
                        class: "flex gap-3 justify-end",

                        button {
                            class: "btn-secondary",
                            disabled: is_unlocking,
                            onclick: move |_| props.on_cancel.call(()),
                            "Cancel"
                        }

                        button {
                            class: "btn-primary",
                            disabled: is_unlocking || password().is_empty(),
                            onclick: handle_submit,

                            if is_unlocking {
                                span {
                                    class: "spinner-sm",
                                }
                                "Unlocking..."
                            } else {
                                "Unlock"
                            }
                        }
                    }
                }
            }
        }
    }
}
