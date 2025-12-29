//! Unlock dialog for entering vault password

use dioxus::prelude::*;

/// Result of an unlock operation
pub type UnlockResult = Result<(), String>;

/// Props for the unlock dialog
#[derive(Props, Clone, PartialEq)]
pub struct UnlockDialogProps {
    /// Vault name to display
    pub vault_name: String,
    /// Called when unlock is attempted with the password
    /// The dialog will manage its own visual state while waiting
    pub on_unlock: EventHandler<String>,
    /// Called when dialog is cancelled
    pub on_cancel: EventHandler<()>,
    /// Called when unlock completes (success or failure)
    /// If None, dialog stays in unlocking state until closed
    #[props(default)]
    pub unlock_result: Option<UnlockResult>,
}

/// State for the unlock dialog
#[derive(Clone, PartialEq, Default)]
pub enum DialogState {
    #[default]
    Idle,
    Unlocking,
    Error(String),
}

/// Password unlock dialog modal
///
/// This component manages its own visual state (idle/unlocking/error) internally
/// to avoid DOM diffing issues when parent components re-render.
#[component]
pub fn UnlockDialog(props: UnlockDialogProps) -> Element {
    let mut password = use_signal(String::new);
    let mut show_password = use_signal(|| false);
    let mut dialog_state = use_signal(|| DialogState::Idle);

    // Track the last result we processed to detect changes
    let mut last_result = use_signal(|| None::<UnlockResult>);

    // Sync external result with internal state when it changes
    // We compare with the previous value to detect actual changes
    if props.unlock_result != *last_result.read() {
        last_result.set(props.unlock_result.clone());
        if let Some(result) = &props.unlock_result {
            match result {
                Ok(()) => {
                    // Success - parent should close the dialog
                    dialog_state.set(DialogState::Idle);
                }
                Err(msg) => {
                    tracing::info!("[UNLOCK_DIALOG] Received error, updating dialog state: {}", msg);
                    dialog_state.set(DialogState::Error(msg.clone()));
                }
            }
        }
    }

    let is_unlocking = matches!(dialog_state(), DialogState::Unlocking);
    let error_message = match dialog_state() {
        DialogState::Error(msg) => Some(msg),
        _ => None,
    };

    let handle_submit = {
        let on_unlock = props.on_unlock;
        move |_| {
            let pw = password();
            if !pw.is_empty() {
                // Set internal state to unlocking BEFORE calling parent
                dialog_state.set(DialogState::Unlocking);
                on_unlock.call(pw);
            }
        }
    };

    let handle_keydown = {
        let on_unlock = props.on_unlock;
        move |e: KeyboardEvent| {
            if e.key() == Key::Enter {
                let pw = password();
                if !pw.is_empty() && !matches!(dialog_state(), DialogState::Unlocking) {
                    dialog_state.set(DialogState::Unlocking);
                    on_unlock.call(pw);
                }
            }
        }
    };

    // Determine button text/content based on state - rendered as separate variables
    // to avoid conditional rendering issues in the button element
    let button_disabled = is_unlocking || password().is_empty();
    let cancel_disabled = is_unlocking;

    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            onclick: move |_| {
                if !is_unlocking {
                    props.on_cancel.call(())
                }
            },

            // Dialog
            div {
                class: "dialog w-[400px]",
                onclick: move |e| e.stop_propagation(),

                // Body
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

                    // Buttons - use stable structure to prevent DOM diffing issues
                    div {
                        class: "flex gap-3 justify-end",

                        button {
                            key: "cancel-btn",
                            class: "btn-secondary",
                            disabled: cancel_disabled,
                            onclick: move |_| props.on_cancel.call(()),
                            "Cancel"
                        }

                        // Primary button with stable structure
                        button {
                            key: "unlock-btn",
                            class: "btn-primary",
                            disabled: button_disabled,
                            onclick: handle_submit,

                            // Spinner - always present but hidden when not unlocking
                            span {
                                class: if is_unlocking { "spinner-sm" } else { "hidden" },
                            }
                            // Text changes based on state
                            if is_unlocking {
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

