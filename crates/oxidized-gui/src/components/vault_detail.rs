//! Vault detail panel component

use dioxus::prelude::*;

use crate::backend::{generate_mountpoint, mount_manager, BackendType};
use crate::dialogs::{BackendDialog, ChangePasswordDialog, ConfirmDialog, ErrorDialog, UnlockDialog, UnlockState};
use crate::error::UserFacingError;
use crate::state::{use_app_state, VaultState};

/// Detail panel showing information and actions for the selected vault
#[component]
pub fn VaultDetail(
    vault_id: String,
    /// Called when the vault is removed from the list
    #[props(default)]
    on_removed: Option<EventHandler<()>>,
) -> Element {
    let mut app_state = use_app_state();
    let mut show_unlock_dialog = use_signal(|| false);
    let mut unlock_state = use_signal(|| UnlockState::Idle);
    let mut show_backend_dialog = use_signal(|| false);
    let mut show_change_password = use_signal(|| false);
    let mut show_remove_confirm = use_signal(|| false);
    let mut error_state = use_signal(|| None::<UserFacingError>);

    let vault = match app_state.read().get_vault(&vault_id) {
        Some(v) => v,
        None => {
            return rsx! {
                div {
                    class: "p-6 text-center text-gray-600 dark:text-gray-400",
                    "Vault not found"
                }
            }
        }
    };

    let (status_icon, status_icon_bg) = match &vault.state {
        VaultState::Locked => ("🔒", "bg-gray-100 dark:bg-neutral-700"),
        VaultState::Mounted { .. } => ("📂", "bg-green-100 dark:bg-green-900/30"),
    };

    // Clone values needed for callbacks
    let vault_name = vault.config.name.clone();
    let vault_path = vault.config.path.clone();
    let preferred_backend = vault.config.preferred_backend;

    // Handle unlock attempt - directly mounts the vault
    let handle_password_submit = {
        let vault_id = vault_id.clone();
        let vault_path = vault_path.clone();
        let vault_name_for_mount = vault_name.clone();
        move |password: String| {
            let vault_id = vault_id.clone();
            let vault_path = vault_path.clone();
            let vault_name = vault_name_for_mount.clone();

            // Set unlocking state
            unlock_state.set(UnlockState::Unlocking);

            spawn(async move {
                // Unlock = mount in one step
                let mountpoint = generate_mountpoint(&vault_name);
                let manager = mount_manager();

                // Clone for use after spawn_blocking
                let vault_id_for_log = vault_id.clone();
                let vault_id_for_state = vault_id.clone();

                // Run mount in blocking task using the vault's preferred backend
                // Pass vault_name for display (volume name in Finder), not the UUID
                let result = tokio::task::spawn_blocking(move || {
                    manager.mount_with_backend(&vault_name, &vault_path, &password, &mountpoint, preferred_backend)
                })
                .await;

                match result {
                    Ok(Ok(mp)) => {
                        tracing::info!("Vault {} mounted at {}", vault_id_for_log, mp.display());
                        app_state.write().set_vault_state(&vault_id_for_state, VaultState::Mounted { mountpoint: mp });
                        show_unlock_dialog.set(false);
                        unlock_state.set(UnlockState::Idle);
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Failed to mount vault: {}", e);
                        let error_msg = match &e {
                            crate::backend::MountError::FilesystemCreation(msg) => {
                                if msg.contains("MasterKeyExtraction")
                                    || msg.contains("Key unwrap failed")
                                    || msg.contains("incorrect passphrase")
                                    || msg.contains("InvalidKey")
                                    || msg.contains("decryption failed")
                                {
                                    "Incorrect password. Please try again.".to_string()
                                } else if msg.contains("vault.cryptomator") || msg.contains("not found") {
                                    "Invalid vault: Could not find vault configuration file.".to_string()
                                } else {
                                    format!("Failed to open vault: {}", msg)
                                }
                            }
                            crate::backend::MountError::Mount(io_err) => {
                                let err_str = io_err.to_string();
                                let err_kind = io_err.kind();
                                let err_str_lower = err_str.to_lowercase();

                                // Permission denied - specific to security settings
                                if err_kind == std::io::ErrorKind::PermissionDenied
                                    || err_str.contains("Permission denied")
                                    || err_str.contains("os error 13")
                                {
                                    match preferred_backend {
                                        crate::state::BackendType::Fuse => {
                                            "Permission denied. Make sure macFUSE is allowed in System Settings → Privacy & Security.".to_string()
                                        }
                                        crate::state::BackendType::FSKit => {
                                            "Permission denied. Check that the FSKit extension is enabled in System Settings.".to_string()
                                        }
                                        _ => "Permission denied. Check filesystem permissions.".to_string()
                                    }
                                }
                                // macFUSE not installed or not loaded - look for specific indicators
                                else if err_str_lower.contains("no such file or directory")
                                    && (err_str_lower.contains("fuse") || err_str_lower.contains("osxfuse") || err_str_lower.contains("macfuse"))
                                {
                                    "FUSE mount failed. Is macFUSE installed? Download from https://osxfuse.github.io/".to_string()
                                }
                                // macFUSE needs kernel extension approval
                                else if err_str_lower.contains("kext") || err_str_lower.contains("system extension")
                                    || err_str_lower.contains("kernel extension")
                                {
                                    "macFUSE kernel extension needs approval. Check System Settings → Privacy & Security.".to_string()
                                }
                                // FSKit bridge connection issues
                                else if preferred_backend == crate::state::BackendType::FSKit
                                    && (err_str_lower.contains("connection refused") || err_str_lower.contains("connection reset"))
                                {
                                    "FSKit mount failed. Make sure FSKitBridge is running.".to_string()
                                }
                                // Timeout
                                else if err_kind == std::io::ErrorKind::TimedOut || err_str.contains("timed out") {
                                    "Mount operation timed out. The filesystem may be slow to respond.".to_string()
                                }
                                // Resource busy
                                else if err_str_lower.contains("busy") || err_str_lower.contains("ebusy") {
                                    "Mount point is busy. Try unmounting any existing mounts first.".to_string()
                                }
                                // Mount point doesn't exist or invalid
                                else if err_kind == std::io::ErrorKind::NotFound {
                                    format!("Mount point not found or inaccessible: {}", io_err)
                                }
                                // Generic fallback - show the actual error
                                else {
                                    format!("{} mount failed: {}", preferred_backend.display_name(), io_err)
                                }
                            }
                            crate::backend::MountError::MountPointNotFound(path) => {
                                format!("Mount location not found: {}", path.display())
                            }
                            crate::backend::MountError::BackendUnavailable(reason) => {
                                format!("{} is not available: {}", preferred_backend.display_name(), reason)
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
            });
        }
    };

    rsx! {
        div {
            // Header
            div {
                class: "flex items-center gap-4 mb-6",

                // Icon container
                div {
                    class: "w-16 h-16 flex items-center justify-center rounded-xl {status_icon_bg}",
                    span {
                        class: "text-3xl",
                        "{status_icon}"
                    }
                }

                div {
                    h2 {
                        class: "mb-1 text-2xl font-semibold text-gray-900 dark:text-gray-100",
                        "{vault.config.name}"
                    }
                    p {
                        class: "text-sm text-gray-500 dark:text-gray-500",
                        "{vault.config.path.display()}"
                    }
                }
            }

            // Status section
            div {
                class: "card p-4 mb-4",

                h3 {
                    class: "mb-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide",
                    "Status"
                }

                div {
                    class: "flex items-center gap-2",

                    // Status badge
                    span {
                        class: if vault.state.is_mounted() { "badge-success" } else { "text-xs px-2 py-0.5 rounded-full font-medium bg-gray-100 dark:bg-neutral-700 text-gray-700 dark:text-gray-300" },
                        "{vault.state.status_text()}"
                    }

                    if let VaultState::Mounted { mountpoint } = &vault.state {
                        span {
                            class: "text-sm text-gray-500",
                            "at {mountpoint.display()}"
                        }
                    }
                }

                div {
                    class: "mt-3 text-sm text-gray-600 dark:text-gray-400 flex items-center gap-2",
                    span { class: "text-gray-500", "Backend:" }
                    span { "{vault.config.preferred_backend.display_name()}" }
                }
            }

            // Actions section
            div {
                class: "card p-4 mb-4",

                h3 {
                    class: "mb-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide",
                    "Actions"
                }

                div {
                    class: "flex flex-col gap-2",

                    match &vault.state {
                        VaultState::Locked => {
                            rsx! {
                                ActionButton {
                                    label: "Unlock Vault",
                                    icon: "🔓",
                                    primary: true,
                                    onclick: move |_| {
                                        unlock_state.set(UnlockState::Idle);
                                        show_unlock_dialog.set(true);
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
                                            error_state.set(Some(
                                                UserFacingError::new("Couldn't Open Vault", format!("Failed to open the vault location: {}", e))
                                                    .with_suggestion("The mount point may no longer exist. Try locking and unlocking the vault.")
                                            ));
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
                                                    error_state.set(Some(
                                                        UserFacingError::new("Couldn't Lock Vault", e.to_string())
                                                            .with_suggestion("Make sure no applications are using files in the vault and try again.")
                                                    ));
                                                }
                                                Err(e) => {
                                                    tracing::error!("Unmount task panicked: {}", e);
                                                    error_state.set(Some(
                                                        UserFacingError::new("Internal Error", "An unexpected error occurred while locking the vault.")
                                                            .with_technical(e.to_string())
                                                    ));
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
                class: "card p-4",

                h3 {
                    class: "mb-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide",
                    "Vault Options"
                }

                div {
                    class: "flex flex-col gap-1",

                    OptionLink {
                        label: "Change Password",
                        onclick: move |_| {
                            show_change_password.set(true);
                        },
                    }

                    OptionLink {
                        label: "Change Backend",
                        onclick: move |_| {
                            show_backend_dialog.set(true);
                        },
                    }

                    OptionLink {
                        label: "Remove from List",
                        danger: true,
                        onclick: move |_| {
                            show_remove_confirm.set(true);
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
                },
            }
        }

        // Backend selection dialog
        if show_backend_dialog() {
            {
                let vault_id_for_backend = vault_id.clone();
                let current_backend = vault.config.preferred_backend;
                rsx! {
                    BackendDialog {
                        current_backend: current_backend,
                        on_select: move |backend: BackendType| {
                            // Update the vault's preferred backend
                            app_state.write().set_vault_backend(&vault_id_for_backend, backend);
                            // Save to disk
                            if let Err(e) = app_state.read().save() {
                                tracing::error!("Failed to save config: {}", e);
                            }
                            show_backend_dialog.set(false);
                        },
                        on_cancel: move |_| {
                            show_backend_dialog.set(false);
                        },
                    }
                }
            }
        }

        // Change password dialog
        if show_change_password() {
            {
                let vault_path_for_change = vault_path.clone();
                let vault_name_for_change = vault_name.clone();
                rsx! {
                    ChangePasswordDialog {
                        vault_path: vault_path_for_change,
                        vault_name: vault_name_for_change,
                        on_complete: move |_| {
                            show_change_password.set(false);
                            // Show success message (optional)
                            tracing::info!("Password changed successfully");
                        },
                        on_cancel: move |_| {
                            show_change_password.set(false);
                        },
                    }
                }
            }
        }

        // Remove vault confirmation dialog
        if show_remove_confirm() {
            {
                let vault_id_for_remove = vault_id.clone();
                let vault_name_for_dialog = vault_name.clone();
                rsx! {
                    ConfirmDialog {
                        title: "Remove Vault?".to_string(),
                        message: format!("Remove \"{}\" from your vault list?", vault_name_for_dialog),
                        warning: Some("This only removes the vault from Oxidized Vault. Your encrypted files will NOT be deleted.".to_string()),
                        confirm_label: "Remove",
                        danger: true,
                        on_confirm: move |_| {
                            // Remove the vault from state
                            app_state.write().remove_vault(&vault_id_for_remove);
                            // Save to disk
                            if let Err(e) = app_state.read().save() {
                                tracing::error!("Failed to save config: {}", e);
                            }
                            show_remove_confirm.set(false);
                            // Notify parent to clear selection
                            if let Some(handler) = &on_removed {
                                handler.call(());
                            }
                        },
                        on_cancel: move |_| {
                            show_remove_confirm.set(false);
                        },
                    }
                }
            }
        }

        // Error dialog
        if let Some(error) = error_state() {
            ErrorDialog {
                error: error,
                on_dismiss: move |_| error_state.set(None),
            }
        }
    }
}

/// A primary or secondary action button
#[component]
fn ActionButton(label: &'static str, icon: &'static str, primary: bool, onclick: EventHandler<()>) -> Element {
    let class = if primary {
        "btn-primary w-full justify-start"
    } else {
        "btn-secondary w-full justify-start"
    };

    rsx! {
        button {
            class: "{class}",
            onclick: move |_| onclick.call(()),

            span { "{icon}" }
            span { "{label}" }
        }
    }
}

/// A link-style option in the options section
#[component]
fn OptionLink(label: &'static str, #[props(default = false)] danger: bool, onclick: EventHandler<()>) -> Element {
    let class = if danger {
        "text-left py-2 text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 bg-transparent border-none cursor-pointer transition-colors"
    } else {
        "text-left py-2 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 bg-transparent border-none cursor-pointer transition-colors"
    };

    rsx! {
        button {
            class: "{class}",
            onclick: move |_| onclick.call(()),
            "{label}"
        }
    }
}
