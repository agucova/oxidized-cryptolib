//! Add existing vault dialog
//!
//! Allows users to add an existing Cryptomator vault to the application.

use dioxus::prelude::*;
use std::path::PathBuf;

use crate::state::{use_app_state, VaultConfig};

/// State for the add vault dialog
#[derive(Clone, PartialEq)]
#[derive(Default)]
pub enum AddVaultState {
    /// Initial state - waiting for folder selection
    #[default]
    SelectFolder,
    /// Folder selected, editing name
    EditName {
        path: PathBuf,
        name: String,
    },
    /// Adding vault in progress
    Adding,
    /// Error occurred
    Error(String),
}


/// Props for the add vault dialog
#[derive(Props, Clone, PartialEq)]
pub struct AddVaultDialogProps {
    /// Called when vault is added successfully
    pub on_complete: EventHandler<()>,
    /// Called when dialog is cancelled
    pub on_cancel: EventHandler<()>,
}

/// Dialog for adding an existing vault
#[component]
pub fn AddVaultDialog(props: AddVaultDialogProps) -> Element {
    let mut state = use_signal(|| AddVaultState::SelectFolder);
    let mut app_state = use_app_state();

    // Handle folder selection
    let handle_select_folder = {
        move |_| {
            spawn(async move {
                // Use rfd for native file dialog
                let folder = rfd::AsyncFileDialog::new()
                    .set_title("Select Cryptomator Vault")
                    .pick_folder()
                    .await;

                if let Some(folder) = folder {
                    let path = folder.path().to_path_buf();

                    // Validate vault structure
                    let vault_config = path.join("vault.cryptomator");
                    if !vault_config.exists() {
                        state.set(AddVaultState::Error(
                            "Selected folder is not a Cryptomator vault. \
                             Please select a folder containing 'vault.cryptomator'."
                                .to_string(),
                        ));
                        return;
                    }

                    // Extract vault name from folder name
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Vault")
                        .to_string();

                    state.set(AddVaultState::EditName { path, name });
                }
            });
        }
    };

    // Handle adding the vault
    let handle_add = {
        move |_| {
            if let AddVaultState::EditName { path, name } = state() {
                if name.trim().is_empty() {
                    state.set(AddVaultState::Error("Vault name cannot be empty".to_string()));
                    return;
                }

                state.set(AddVaultState::Adding);

                // Create vault config and add to app state
                let config = VaultConfig::new(&name, path.clone());
                app_state.write().add_vault(config);

                // Save config
                if let Err(e) = app_state.read().save() {
                    tracing::error!("Failed to save config: {}", e);
                    state.set(AddVaultState::Error(format!("Failed to save: {}", e)));
                    return;
                }

                tracing::info!("Added vault '{}' at {}", name, path.display());
                props.on_complete.call(());
            }
        }
    };

    // Handle name change
    let handle_name_change = move |e: Event<FormData>| {
        if let AddVaultState::EditName { path, .. } = state() {
            state.set(AddVaultState::EditName {
                path,
                name: e.value(),
            });
        }
    };

    // Handle back button
    let handle_back = move |_| {
        state.set(AddVaultState::SelectFolder);
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
                    width: 480px;
                    max-width: 90vw;
                    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
                ",
                onclick: move |e| e.stop_propagation(),

                // Header
                h2 {
                    style: "margin: 0 0 8px 0; font-size: 20px; font-weight: 600; color: #1a1a1a;",
                    "Add Existing Vault"
                }

                match state() {
                    AddVaultState::SelectFolder => {
                        rsx! {
                            p {
                                style: "margin: 0 0 20px 0; font-size: 14px; color: #666;",
                                "Select a folder containing a Cryptomator vault."
                            }

                            // Select folder button (centered)
                            div {
                                style: "
                                    display: flex;
                                    flex-direction: column;
                                    align-items: center;
                                    padding: 32px;
                                    border: 2px dashed #ddd;
                                    border-radius: 8px;
                                    margin-bottom: 20px;
                                ",

                                span {
                                    style: "font-size: 48px; margin-bottom: 16px;",
                                    "📁"
                                }

                                button {
                                    style: "
                                        padding: 12px 24px;
                                        background: #2196f3;
                                        color: white;
                                        border: none;
                                        border-radius: 6px;
                                        font-size: 14px;
                                        font-weight: 500;
                                        cursor: pointer;
                                    ",
                                    onclick: handle_select_folder,
                                    "Choose Vault Folder"
                                }
                            }

                            // Cancel button
                            div {
                                style: "display: flex; justify-content: flex-end;",

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
                            }
                        }
                    },

                    AddVaultState::EditName { ref path, ref name } => {
                        rsx! {
                            p {
                                style: "margin: 0 0 20px 0; font-size: 14px; color: #666;",
                                "Enter a name for this vault."
                            }

                            // Path display
                            div {
                                style: "
                                    margin-bottom: 16px;
                                    padding: 12px;
                                    background: #f5f5f5;
                                    border-radius: 6px;
                                    font-size: 13px;
                                    color: #666;
                                    word-break: break-all;
                                ",
                                "{path.display()}"
                            }

                            // Name input
                            div {
                                style: "margin-bottom: 20px;",

                                label {
                                    style: "display: block; font-size: 13px; color: #666; margin-bottom: 6px;",
                                    "Vault Name"
                                }

                                input {
                                    r#type: "text",
                                    style: "
                                        width: 100%;
                                        padding: 12px;
                                        border: 1px solid #ddd;
                                        border-radius: 6px;
                                        font-size: 14px;
                                        box-sizing: border-box;
                                        outline: none;
                                    ",
                                    value: "{name}",
                                    oninput: handle_name_change,
                                    autofocus: true,
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
                                    onclick: handle_back,
                                    "Back"
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
                                    disabled: name.trim().is_empty(),
                                    onclick: handle_add,
                                    "Add Vault"
                                }
                            }
                        }
                    },

                    AddVaultState::Adding => {
                        rsx! {
                            div {
                                style: "
                                    display: flex;
                                    flex-direction: column;
                                    align-items: center;
                                    padding: 32px;
                                ",

                                div {
                                    style: "
                                        width: 40px;
                                        height: 40px;
                                        border: 3px solid #e0e0e0;
                                        border-top-color: #2196f3;
                                        border-radius: 50%;
                                        animation: spin 0.8s linear infinite;
                                        margin-bottom: 16px;
                                    ",
                                }

                                span {
                                    style: "font-size: 14px; color: #666;",
                                    "Adding vault..."
                                }
                            }

                            style { "
                                @keyframes spin {{
                                    to {{ transform: rotate(360deg); }}
                                }}
                            " }
                        }
                    },

                    AddVaultState::Error(ref error) => {
                        rsx! {
                            // Error message
                            div {
                                style: "
                                    margin-bottom: 20px;
                                    padding: 12px;
                                    background: #fef2f2;
                                    border: 1px solid #fecaca;
                                    border-radius: 6px;
                                    color: #dc2626;
                                    font-size: 13px;
                                ",
                                "{error}"
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
                                    onclick: move |_| state.set(AddVaultState::SelectFolder),
                                    "Try Again"
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}
