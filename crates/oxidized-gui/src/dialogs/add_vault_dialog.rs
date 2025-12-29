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

                // Create vault config with the default backend from settings
                let default_backend = app_state.read().config.default_backend;
                let config = VaultConfig::with_backend(&name, path.clone(), default_backend);
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
            class: "dialog-backdrop",
            onclick: move |_| props.on_cancel.call(()),

            // Dialog
            div {
                class: "dialog w-[480px]",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "dialog-body",

                    h2 {
                        class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                        "Add Existing Vault"
                    }

                    match state() {
                        AddVaultState::SelectFolder => {
                            rsx! {
                                p {
                                    class: "mb-5 text-sm text-gray-600 dark:text-gray-400",
                                    "Select a folder containing a Cryptomator vault."
                                }

                                // Select folder button (centered)
                                div {
                                    class: "dropzone",

                                    span {
                                        class: "text-5xl mb-4",
                                        "📁"
                                    }

                                    button {
                                        class: "btn-primary",
                                        onclick: handle_select_folder,
                                        "Choose Vault Folder"
                                    }
                                }
                            }
                        },

                        AddVaultState::EditName { ref path, ref name } => {
                            rsx! {
                                p {
                                    class: "mb-5 text-sm text-gray-600 dark:text-gray-400",
                                    "Enter a name for this vault."
                                }

                                // Path display
                                div {
                                    class: "mb-4 p-3 bg-gray-100 dark:bg-neutral-700 rounded-md text-sm text-gray-600 dark:text-gray-400 break-all",
                                    "{path.display()}"
                                }

                                // Name input
                                div {
                                    class: "mb-5",

                                    label {
                                        class: "label",
                                        "Vault Name"
                                    }

                                    input {
                                        r#type: "text",
                                        class: "input",
                                        value: "{name}",
                                        oninput: handle_name_change,
                                        autofocus: true,
                                    }
                                }
                            }
                        },

                        AddVaultState::Adding => {
                            rsx! {
                                div {
                                    class: "flex flex-col items-center p-8",

                                    span {
                                        class: "spinner mb-4",
                                    }

                                    span {
                                        class: "text-sm text-gray-600 dark:text-gray-400",
                                        "Adding vault..."
                                    }
                                }
                            }
                        },

                        AddVaultState::Error(ref error) => {
                            rsx! {
                                // Error message
                                div {
                                    class: "alert-danger mb-5",
                                    "{error}"
                                }
                            }
                        },
                    }
                }

                // Footer with buttons
                div {
                    class: "dialog-footer",

                    match state() {
                        AddVaultState::SelectFolder => {
                            rsx! {
                                button {
                                    class: "btn-secondary",
                                    onclick: move |_| props.on_cancel.call(()),
                                    "Cancel"
                                }
                            }
                        },
                        AddVaultState::EditName { ref name, .. } => {
                            rsx! {
                                button {
                                    class: "btn-secondary",
                                    onclick: handle_back,
                                    "Back"
                                }

                                button {
                                    class: "btn-primary",
                                    disabled: name.trim().is_empty(),
                                    onclick: handle_add,
                                    "Add Vault"
                                }
                            }
                        },
                        AddVaultState::Adding => {
                            rsx! {}
                        },
                        AddVaultState::Error(_) => {
                            rsx! {
                                button {
                                    class: "btn-secondary",
                                    onclick: move |_| props.on_cancel.call(()),
                                    "Cancel"
                                }

                                button {
                                    class: "btn-primary",
                                    onclick: move |_| state.set(AddVaultState::SelectFolder),
                                    "Try Again"
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}
