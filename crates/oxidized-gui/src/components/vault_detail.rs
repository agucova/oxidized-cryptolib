//! Vault detail panel component

use dioxus::prelude::*;
use oxidized_cryptolib::VaultOperationsAsync;

use crate::backend::{generate_mountpoint, mount_manager};
use crate::dialogs::{UnlockDialog, UnlockState};
use crate::state::{use_app_state, VaultState};

/// Detail panel showing information and actions for the selected vault
#[component]
pub fn VaultDetail(vault_id: String) -> Element {
    let mut app_state = use_app_state();
    let mut show_unlock_dialog = use_signal(|| false);
    let mut unlock_state = use_signal(|| UnlockState::Idle);
    // Track whether we're mounting (true) or just unlocking (false)
    let mut is_mount_mode = use_signal(|| false);

    let vault = match app_state.read().get_vault(&vault_id) {
        Some(v) => v,
        None => {
            return rsx! {
                div {
                    style: "padding: 24px; text-align: center; color: #666;",
                    "Vault not found"
                }
            }
        }
    };

    let status_icon = match &vault.state {
        VaultState::Locked => "🔒",
        VaultState::Unlocked => "🔓",
        VaultState::Mounted { .. } => "📂",
    };

    // Clone values needed for callbacks
    let vault_name = vault.config.name.clone();
    let vault_path = vault.config.path.clone();

    // Handle unlock/mount attempt (based on is_mount_mode)
    let handle_password_submit = {
        let vault_id = vault_id.clone();
        let vault_path = vault_path.clone();
        let vault_name_for_mount = vault_name.clone();
        move |password: String| {
            let vault_id = vault_id.clone();
            let vault_path = vault_path.clone();
            let vault_name = vault_name_for_mount.clone();
            let should_mount = is_mount_mode();

            // Set unlocking state
            unlock_state.set(UnlockState::Unlocking);

            spawn(async move {
                if should_mount {
                    // Mount mode: use MountManager to mount the vault
                    let mountpoint = generate_mountpoint(&vault_name);
                    let manager = mount_manager();

                    // Clone for use after spawn_blocking
                    let vault_id_for_log = vault_id.clone();
                    let vault_id_for_state = vault_id.clone();

                    // Run mount in blocking task (involves scrypt + FUSE)
                    let result = tokio::task::spawn_blocking(move || {
                        manager.mount(&vault_id, &vault_path, &password, &mountpoint)
                    })
                    .await;

                    match result {
                        Ok(Ok(mp)) => {
                            tracing::info!("Vault {} mounted at {}", vault_id_for_log, mp.display());
                            app_state.write().set_vault_state(&vault_id_for_state, VaultState::Mounted { mountpoint: mp });
                            show_unlock_dialog.set(false);
                            unlock_state.set(UnlockState::Idle);
                            is_mount_mode.set(false);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Failed to mount vault: {}", e);
                            let error_msg = match &e {
                                crate::backend::MountError::FilesystemCreation(msg) => {
                                    if msg.contains("MasterKeyExtraction") {
                                        "Incorrect password. Please try again.".to_string()
                                    } else {
                                        format!("Failed to create filesystem: {}", msg)
                                    }
                                }
                                crate::backend::MountError::Mount(io_err) => {
                                    format!("Mount failed: {}", io_err)
                                }
                                other => format!("Mount failed: {}", other),
                            };
                            unlock_state.set(UnlockState::Error(error_msg));
                        }
                        Err(e) => {
                            tracing::error!("Mount task panicked: {}", e);
                            unlock_state.set(UnlockState::Error("Internal error occurred".to_string()));
                        }
                    }
                } else {
                    // Unlock mode: just validate password
                    let result = tokio::task::spawn_blocking(move || {
                        VaultOperationsAsync::open(&vault_path, &password)
                    })
                    .await;

                    match result {
                        Ok(Ok(_ops)) => {
                            tracing::info!("Vault {} unlocked successfully", vault_id);
                            app_state.write().set_vault_state(&vault_id, VaultState::Unlocked);
                            show_unlock_dialog.set(false);
                            unlock_state.set(UnlockState::Idle);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Failed to unlock vault: {}", e);
                            let error_msg = match &e {
                                oxidized_cryptolib::vault::VaultError::MasterKeyExtraction(_) => {
                                    "Incorrect password. Please try again.".to_string()
                                }
                                oxidized_cryptolib::vault::VaultError::Io(io_err) => {
                                    format!("Could not access vault: {}", io_err)
                                }
                                other => format!("Unlock failed: {}", other),
                            };
                            unlock_state.set(UnlockState::Error(error_msg));
                        }
                        Err(e) => {
                            tracing::error!("Unlock task panicked: {}", e);
                            unlock_state.set(UnlockState::Error("Internal error occurred".to_string()));
                        }
                    }
                }
            });
        }
    };

    rsx! {
        div {
            class: "vault-detail",

            // Header
            div {
                style: "display: flex; align-items: center; gap: 16px; margin-bottom: 24px;",

                span {
                    style: "font-size: 48px;",
                    "{status_icon}"
                }

                div {
                    h2 {
                        style: "margin: 0 0 4px 0; font-size: 24px; font-weight: 600; color: #1a1a1a;",
                        "{vault.config.name}"
                    }
                    p {
                        style: "margin: 0; font-size: 14px; color: #666;",
                        "{vault.config.path.display()}"
                    }
                }
            }

            // Status section
            div {
                style: "background: #fff; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);",

                h3 {
                    style: "margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.5px;",
                    "Status"
                }

                div {
                    style: "display: flex; align-items: center; gap: 8px;",

                    span {
                        style: "font-size: 14px; color: #1a1a1a;",
                        "{vault.state.status_text()}"
                    }

                    if let VaultState::Mounted { mountpoint } = &vault.state {
                        span {
                            style: "font-size: 12px; color: #666;",
                            "at {mountpoint.display()}"
                        }
                    }
                }

                div {
                    style: "margin-top: 8px; font-size: 12px; color: #666;",
                    "Backend: {vault.config.preferred_backend.display_name()}"
                }
            }

            // Actions section
            div {
                style: "background: #fff; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);",

                h3 {
                    style: "margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.5px;",
                    "Actions"
                }

                div {
                    style: "display: flex; flex-direction: column; gap: 8px;",

                    match &vault.state {
                        VaultState::Locked => {
                            rsx! {
                                ActionButton {
                                    label: "Unlock Vault",
                                    icon: "🔓",
                                    primary: true,
                                    onclick: move |_| {
                                        is_mount_mode.set(false);
                                        unlock_state.set(UnlockState::Idle);
                                        show_unlock_dialog.set(true);
                                    },
                                }
                            }
                        },
                        VaultState::Unlocked => {
                            let id2 = vault_id.clone();
                            rsx! {
                                ActionButton {
                                    label: "Mount Vault",
                                    icon: "📂",
                                    primary: true,
                                    onclick: move |_| {
                                        // Set mount mode and show password dialog
                                        is_mount_mode.set(true);
                                        unlock_state.set(UnlockState::Idle);
                                        show_unlock_dialog.set(true);
                                    },
                                }
                                ActionButton {
                                    label: "Lock Vault",
                                    icon: "🔒",
                                    primary: false,
                                    onclick: move |_| {
                                        app_state.write().set_vault_state(&id2, VaultState::Locked);
                                    },
                                }
                            }
                        },
                        VaultState::Mounted { mountpoint } => {
                            let mp = mountpoint.clone();
                            let id_for_unmount = vault_id.clone();
                            rsx! {
                                ActionButton {
                                    label: "Reveal in Finder",
                                    icon: "📁",
                                    primary: true,
                                    onclick: move |_| {
                                        if let Err(e) = open::that(&mp) {
                                            tracing::error!("Failed to open {}: {}", mp.display(), e);
                                        }
                                    },
                                }
                                ActionButton {
                                    label: "Lock Vault",
                                    icon: "🔐",
                                    primary: false,
                                    onclick: move |_| {
                                        // Unmount and lock the vault
                                        let vault_id = id_for_unmount.clone();
                                        let vault_id_for_log = vault_id.clone();
                                        let vault_id_for_state = vault_id.clone();
                                        spawn(async move {
                                            let manager = mount_manager();
                                            let result = tokio::task::spawn_blocking(move || {
                                                manager.unmount(&vault_id)
                                            }).await;

                                            match result {
                                                Ok(Ok(())) => {
                                                    tracing::info!("Vault {} unmounted and locked", vault_id_for_log);
                                                    app_state.write().set_vault_state(&vault_id_for_state, VaultState::Locked);
                                                }
                                                Ok(Err(e)) => {
                                                    tracing::error!("Failed to unmount vault: {}", e);
                                                }
                                                Err(e) => {
                                                    tracing::error!("Unmount task panicked: {}", e);
                                                }
                                            }
                                        });
                                    },
                                }
                            }
                        },
                    }
                }
            }

            // Options section
            div {
                style: "background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);",

                h3 {
                    style: "margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.5px;",
                    "Vault Options"
                }

                div {
                    style: "display: flex; flex-direction: column; gap: 8px;",

                    OptionLink {
                        label: "Change Password",
                        onclick: move |_| {
                            tracing::info!("TODO: Open change password dialog");
                        },
                    }

                    OptionLink {
                        label: "Change Backend",
                        onclick: move |_| {
                            tracing::info!("TODO: Open backend selection");
                        },
                    }

                    OptionLink {
                        label: "Remove from List",
                        danger: true,
                        onclick: move |_| {
                            tracing::info!("TODO: Confirm and remove vault from list");
                        },
                    }
                }
            }
        }

        // Unlock/Mount dialog (rendered at root level for proper overlay)
        if show_unlock_dialog() {
            UnlockDialog {
                vault_name: vault_name.clone(),
                state: unlock_state(),
                on_unlock: handle_password_submit,
                on_cancel: move |_| {
                    show_unlock_dialog.set(false);
                    unlock_state.set(UnlockState::Idle);
                    is_mount_mode.set(false);
                },
            }
        }
    }
}

/// A primary or secondary action button
#[component]
fn ActionButton(label: &'static str, icon: &'static str, primary: bool, onclick: EventHandler<()>) -> Element {
    let bg = if primary { "#2196f3" } else { "#f5f5f5" };
    let color = if primary { "#fff" } else { "#333" };

    rsx! {
        button {
            style: "
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 12px 16px;
                background: {bg};
                color: {color};
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                transition: background 0.15s ease;
            ",
            onclick: move |_| onclick.call(()),

            span { "{icon}" }
            span { "{label}" }
        }
    }
}

/// A link-style option in the options section
#[component]
fn OptionLink(label: &'static str, #[props(default = false)] danger: bool, onclick: EventHandler<()>) -> Element {
    let color = if danger { "#f44336" } else { "#2196f3" };

    rsx! {
        button {
            style: "
                background: none;
                border: none;
                padding: 8px 0;
                color: {color};
                font-size: 14px;
                cursor: pointer;
                text-align: left;
            ",
            onclick: move |_| onclick.call(()),
            "{label}"
        }
    }
}
