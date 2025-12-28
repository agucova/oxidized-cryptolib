//! Unlock dialog for entering vault password

use dioxus::prelude::*;

/// State for the unlock dialog
#[derive(Clone, PartialEq)]
pub enum UnlockState {
    /// Waiting for user input
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

impl Default for UnlockState {
    fn default() -> Self {
        Self::Idle
    }
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
        let on_unlock = props.on_unlock.clone();
        move |_| {
            let pw = password();
            if !pw.is_empty() {
                on_unlock.call(pw);
            }
        }
    };

    let handle_keydown = {
        let on_unlock = props.on_unlock.clone();
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
                    width: 400px;
                    max-width: 90vw;
                    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
                ",
                onclick: move |e| e.stop_propagation(),

                // Header
                h2 {
                    style: "margin: 0 0 8px 0; font-size: 20px; font-weight: 600; color: #1a1a1a;",
                    "Unlock Vault"
                }

                p {
                    style: "margin: 0 0 20px 0; font-size: 14px; color: #666;",
                    "Enter the password for \"{props.vault_name}\""
                }

                // Password input
                div {
                    style: "margin-bottom: 16px;",

                    div {
                        style: "position: relative;",

                        input {
                            r#type: if show_password() { "text" } else { "password" },
                            style: "
                                width: 100%;
                                padding: 12px 40px 12px 12px;
                                border: 1px solid #ddd;
                                border-radius: 6px;
                                font-size: 14px;
                                box-sizing: border-box;
                                outline: none;
                            ",
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
                            style: "
                                position: absolute;
                                right: 8px;
                                top: 50%;
                                transform: translateY(-50%);
                                background: none;
                                border: none;
                                cursor: pointer;
                                font-size: 16px;
                                padding: 4px;
                            ",
                            onclick: move |_| show_password.set(!show_password()),
                            if show_password() { "🙈" } else { "👁️" }
                        }
                    }
                }

                // Error message
                if let Some(error) = error_message {
                    div {
                        style: "
                            margin-bottom: 16px;
                            padding: 12px;
                            background: #fef2f2;
                            border: 1px solid #fecaca;
                            border-radius: 6px;
                            color: #dc2626;
                            font-size: 13px;
                        ",
                        "{error}"
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
                        disabled: is_unlocking,
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
                            display: flex;
                            align-items: center;
                            gap: 8px;
                        ",
                        disabled: is_unlocking || password().is_empty(),
                        onclick: handle_submit,

                        if is_unlocking {
                            span {
                                style: "
                                    width: 14px;
                                    height: 14px;
                                    border: 2px solid #ffffff40;
                                    border-top-color: white;
                                    border-radius: 50%;
                                    animation: spin 0.8s linear infinite;
                                ",
                            }
                            "Unlocking..."
                        } else {
                            "Unlock"
                        }
                    }
                }
            }
        }

        // CSS animation for spinner
        style { "
            @keyframes spin {{
                to {{ transform: rotate(360deg); }}
            }}
        " }
    }
}
