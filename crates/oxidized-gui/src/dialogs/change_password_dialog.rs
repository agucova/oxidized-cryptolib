//! Change password dialog for updating vault password

use dioxus::prelude::*;
use std::path::PathBuf;

/// State for the change password dialog
#[derive(Clone, PartialEq, Default)]
pub enum ChangePasswordState {
    /// Waiting for user input
    #[default]
    Idle,
    /// Currently changing password
    Changing,
    /// Change failed with error message
    Error(String),
}

/// Props for the change password dialog
#[derive(Props, Clone, PartialEq)]
pub struct ChangePasswordDialogProps {
    /// Path to the vault
    pub vault_path: PathBuf,
    /// Vault name to display
    pub vault_name: String,
    /// Called when password change succeeds
    pub on_complete: EventHandler<()>,
    /// Called when dialog is cancelled
    pub on_cancel: EventHandler<()>,
}

/// Password change dialog modal
#[component]
pub fn ChangePasswordDialog(props: ChangePasswordDialogProps) -> Element {
    let mut current_password = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut confirm_password = use_signal(String::new);
    let mut show_current = use_signal(|| false);
    let mut show_new = use_signal(|| false);
    let mut state = use_signal(ChangePasswordState::default);

    let is_changing = matches!(state(), ChangePasswordState::Changing);
    let error_message = match state() {
        ChangePasswordState::Error(msg) => Some(msg),
        _ => None,
    };

    // Validation
    let passwords_match = new_password() == confirm_password();
    let new_password_empty = new_password().is_empty();
    let can_submit = !current_password().is_empty()
        && !new_password_empty
        && passwords_match
        && !is_changing;

    let handle_submit = {
        let vault_path = props.vault_path.clone();
        let on_complete = props.on_complete;
        move |_| {
            if !can_submit {
                return;
            }

            state.set(ChangePasswordState::Changing);

            let path = vault_path.clone();
            let old_pw = current_password();
            let new_pw = new_password();

            spawn(async move {
                // Use the async change_password function from oxidized-cryptolib
                let masterkey_dir = path.join("masterkey");
                let result = tokio::task::spawn_blocking({
                    let masterkey_path = masterkey_dir.clone().join("masterkey.cryptomator");
                    move || {
                        oxidized_cryptolib::vault::change_password(
                            &masterkey_path,
                            &old_pw,
                            &new_pw,
                        )
                    }
                })
                .await;

                match result {
                    Ok(Ok(new_content)) => {
                        // Atomic write: write to temp file, then rename
                        let temp_path = masterkey_dir.join("masterkey.cryptomator.tmp");
                        let masterkey_path = masterkey_dir.join("masterkey.cryptomator");

                        match tokio::fs::write(&temp_path, &new_content).await {
                            Ok(()) => {
                                match tokio::fs::rename(&temp_path, &masterkey_path).await {
                                    Ok(()) => {
                                        state.set(ChangePasswordState::Idle);
                                        on_complete.call(());
                                    }
                                    Err(e) => {
                                        state.set(ChangePasswordState::Error(format!(
                                            "Failed to save new password: {}",
                                            e
                                        )));
                                    }
                                }
                            }
                            Err(e) => {
                                state.set(ChangePasswordState::Error(format!(
                                    "Failed to write new password: {}",
                                    e
                                )));
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        let msg = if e.to_string().contains("integrity")
                            || e.to_string().contains("Unwrap")
                        {
                            "Incorrect current password".to_string()
                        } else {
                            format!("Failed to change password: {}", e)
                        };
                        state.set(ChangePasswordState::Error(msg));
                    }
                    Err(e) => {
                        state.set(ChangePasswordState::Error(format!("Task error: {}", e)));
                    }
                }
            });
        }
    };

    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            onclick: move |_| {
                if !is_changing {
                    props.on_cancel.call(());
                }
            },

            // Dialog
            div {
                class: "dialog w-[420px]",
                onclick: move |e| e.stop_propagation(),

                // Body
                div {
                    class: "dialog-body",

                    // Header
                    h2 {
                        class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                        "Change Password"
                    }

                    p {
                        class: "mb-5 text-sm text-gray-600 dark:text-gray-400",
                        "Change password for \"{props.vault_name}\""
                    }

                    // Current password input
                    div {
                        class: "mb-4",

                        label {
                            class: "label",
                            "Current Password"
                        }

                        div {
                            class: "input-group",

                            input {
                                r#type: if show_current() { "text" } else { "password" },
                                class: "input pr-11",
                                placeholder: "Enter current password",
                                disabled: is_changing,
                                value: "{current_password}",
                                oninput: move |e| current_password.set(e.value()),
                                autofocus: true,
                            }

                            button {
                                r#type: "button",
                                class: "input-icon bg-transparent border-none cursor-pointer text-base p-1",
                                onclick: move |_| show_current.set(!show_current()),
                                if show_current() { "🙈" } else { "👁️" }
                            }
                        }
                    }

                    // New password input
                    div {
                        class: "mb-4",

                        label {
                            class: "label",
                            "New Password"
                        }

                        div {
                            class: "input-group",

                            input {
                                r#type: if show_new() { "text" } else { "password" },
                                class: "input pr-11",
                                placeholder: "Enter new password",
                                disabled: is_changing,
                                value: "{new_password}",
                                oninput: move |e| new_password.set(e.value()),
                            }

                            button {
                                r#type: "button",
                                class: "input-icon bg-transparent border-none cursor-pointer text-base p-1",
                                onclick: move |_| show_new.set(!show_new()),
                                if show_new() { "🙈" } else { "👁️" }
                            }
                        }
                    }

                    // Confirm password input
                    div {
                        class: "mb-4",

                        label {
                            class: "label",
                            "Confirm New Password"
                        }

                        input {
                            r#type: if show_new() { "text" } else { "password" },
                            class: if !confirm_password().is_empty() && !passwords_match { "input input-error" } else { "input" },
                            placeholder: "Confirm new password",
                            disabled: is_changing,
                            value: "{confirm_password}",
                            oninput: move |e| confirm_password.set(e.value()),
                        }

                        // Mismatch warning
                        if !confirm_password().is_empty() && !passwords_match {
                            p {
                                class: "mt-1 text-sm text-red-600 dark:text-red-400",
                                "Passwords don't match"
                            }
                        }
                    }

                    // Warning message
                    div {
                        class: "alert-warning mb-4",
                        "Make sure to remember your new password. There is no way to recover your data if you forget it."
                    }

                    // Error message
                    if let Some(error) = error_message {
                        div {
                            class: "alert-danger mb-4",
                            "{error}"
                        }
                    }
                }

                // Footer with buttons
                div {
                    class: "dialog-footer",

                    button {
                        class: "btn-secondary",
                        disabled: is_changing,
                        onclick: move |_| props.on_cancel.call(()),
                        "Cancel"
                    }

                    button {
                        class: "btn-primary",
                        disabled: !can_submit,
                        onclick: handle_submit,

                        if is_changing {
                            span {
                                class: "spinner spinner-sm",
                            }
                            "Changing..."
                        } else {
                            "Change Password"
                        }
                    }
                }
            }
        }
    }
}
