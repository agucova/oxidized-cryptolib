//! Vault detail panel component

use dioxus::prelude::*;
use oxcrypt_mount::{find_processes_using_mount, format_bytes, ProcessInfo};
use std::time::Duration;

use crate::icons::{Icon, IconName, IconSize};

/// Context for force lock dialog - tracks what triggered the dialog
#[derive(Clone, Copy, PartialEq, Default)]
enum ForceLockContext {
    /// User clicked "Lock Vault"
    #[default]
    Lock,
    /// User clicked "Change Backend" and needs to unmount first
    BackendChange,
}

use crate::backend::{generate_mountpoint, mount_manager, MountOptions};
use crate::app::open_stats_window;
use crate::dialogs::{BackendDialog, ChangePasswordDialog, ConfirmDialog, ErrorDialog, ForceLockDialog, UnlockDialog, VaultMountSettings};
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
    let mut unlock_result = use_signal(|| None::<Result<(), String>>);
    let mut show_backend_dialog = use_signal(|| false);
    let mut show_change_password = use_signal(|| false);
    let mut show_remove_confirm = use_signal(|| false);
    let mut show_dropdown = use_signal(|| false);
    let mut error_state = use_signal(|| None::<UserFacingError>);

    // Force lock dialog state
    let mut show_force_lock_dialog = use_signal(|| false);
    let mut force_lock_error = use_signal(String::new);
    let mut blocking_processes = use_signal(Vec::<ProcessInfo>::new);
    let mut force_lock_context = use_signal(|| ForceLockContext::Lock);

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

    let (status_icon_name, status_icon_class) = match &vault.state {
        VaultState::Locked => (IconName::Lock, "vault-detail-icon vault-detail-icon-locked"),
        VaultState::Mounted { .. } => (IconName::FolderOpen, "vault-detail-icon vault-detail-icon-mounted"),
    };

    // Clone values needed for callbacks
    let vault_name = vault.config.name.clone();
    let vault_path = vault.config.path.clone();
    let preferred_backend = vault.config.preferred_backend;
    let local_mode = vault.config.local_mode;

    // Handle unlock attempt - directly mounts the vault
    let handle_password_submit = {
        let vault_id = vault_id.clone();
        let vault_path = vault_path.clone();
        let vault_name = vault_name.clone();
        move |password: String| {
            tracing::info!("[UNLOCK] handle_password_submit callback invoked");
            let vault_id = vault_id.clone();
            let vault_path = vault_path.clone();
            let vault_name = vault_name.clone();

            // Dialog now manages its own visual "unlocking" state internally
            // We just need to clear any previous error result
            unlock_result.set(None);
            tracing::info!("[UNLOCK] Cleared previous result, spawning async task...");

            spawn(async move {
                // Two-phase unlock: validate password first, then mount
                // This gives fast feedback on wrong passwords and protects against stale mounts
                use oxcrypt_core::vault::{PasswordValidator, PasswordValidationError, DEFAULT_VALIDATION_TIMEOUT};

                tracing::info!("[UNLOCK] Async task started for vault at {:?}", vault_path);

                // Phase 1: Validate password with timeout protection
                let vault_path_for_validation = vault_path.clone();
                let password_for_validation = password.clone();
                tracing::info!("[UNLOCK] Phase 1: About to spawn_blocking for password validation...");
                let validation_result = tokio::task::spawn_blocking(move || {
                    tracing::info!("[UNLOCK] spawn_blocking: ENTERED - Creating PasswordValidator");
                    let validator = PasswordValidator::new(&vault_path_for_validation);
                    tracing::info!("[UNLOCK] spawn_blocking: Calling validate() with {:?} timeout", DEFAULT_VALIDATION_TIMEOUT);
                    let result = validator.validate(&password_for_validation, DEFAULT_VALIDATION_TIMEOUT);
                    tracing::info!("[UNLOCK] spawn_blocking: validate() returned: {:?}", result.as_ref().map(|_| "Ok").unwrap_or("Err"));
                    result
                }).await;
                tracing::info!("[UNLOCK] Phase 1: spawn_blocking completed, processing result...");

                // Handle validation result
                let _validated = match validation_result {
                    Ok(Ok(validated)) => {
                        tracing::debug!("Password validated successfully");
                        validated
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("[UNLOCK] Password validation failed: {}", e);
                        let error_msg = match e {
                            PasswordValidationError::IncorrectPassword => {
                                "Incorrect password. Please try again.".to_string()
                            }
                            PasswordValidationError::Timeout => {
                                "Vault access timed out. The vault location may be on a stale or unresponsive mount.".to_string()
                            }
                            PasswordValidationError::ConfigNotFound(path) => {
                                format!("Vault configuration not found: {}", path.display())
                            }
                            PasswordValidationError::MasterKeyNotFound(path) => {
                                format!("Master key file not found: {}", path.display())
                            }
                            PasswordValidationError::InvalidFormat(msg) => {
                                format!("Invalid vault format: {}", msg)
                            }
                            PasswordValidationError::Io(io_err) => {
                                format!("Failed to read vault files: {}", io_err)
                            }
                            PasswordValidationError::Parse(json_err) => {
                                format!("Failed to parse vault files: {}", json_err)
                            }
                            PasswordValidationError::JwtValidation(jwt_err) => {
                                format!("Vault configuration validation failed: {}", jwt_err)
                            }
                            PasswordValidationError::Crypto(crypto_err) => {
                                format!("Cryptographic error: {}", crypto_err)
                            }
                        };
                        tracing::info!("[UNLOCK] About to set unlock_result with error: {}", error_msg);
                        unlock_result.set(Some(Err(error_msg)));
                        tracing::info!("[UNLOCK] unlock_result.set() completed, returning from async task");
                        return;
                    }
                    Err(e) => {
                        tracing::error!("[UNLOCK] Validation task panicked: {}", e);
                        unlock_result.set(Some(Err("Internal error during password validation".to_string())));
                        tracing::info!("[UNLOCK] unlock_result.set() completed after panic, returning");
                        return;
                    }
                };

                // Phase 2: Mount the vault (password is now known to be correct)
                let mountpoint = generate_mountpoint(&vault_name);
                let manager = mount_manager();

                // Clone for use after spawn_blocking
                let vault_id_for_log = vault_id.clone();
                let vault_id_for_state = vault_id.clone();

                // Create mount options with local_mode from vault config
                let mount_options = MountOptions {
                    local_mode,
                    attr_ttl: None, // Use defaults based on local_mode
                    negative_ttl: None,
                    background_refresh: None,
                    concurrency_limit: None,
                };

                // Run mount in blocking task using the vault's preferred backend
                // Use vault_id as the key for mount tracking (must match unmount calls)
                let result = tokio::task::spawn_blocking(move || {
                    manager.mount_with_backend_and_options(&vault_id, &vault_path, &password, &mountpoint, preferred_backend, &mount_options)
                })
                .await;

                match result {
                    Ok(Ok(mp)) => {
                        tracing::info!("Vault {} mounted at {}", vault_id_for_log, mp.display());
                        app_state.write().set_vault_state(&vault_id_for_state, VaultState::Mounted { mountpoint: mp });
                        // Success - close dialog (result will be set but dialog won't see it)
                        unlock_result.set(Some(Ok(())));
                        show_unlock_dialog.set(false);
                    }
                    Ok(Err(e)) => {
                        // Password was already validated, so this is a mount-specific error
                        tracing::warn!("Failed to mount vault (password already validated): {}", e);
                        let error_msg = match &e {
                            crate::backend::MountError::FilesystemCreation(msg) => {
                                // Password errors shouldn't happen here since we validated first,
                                // but handle them just in case
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
                        unlock_result.set(Some(Err(error_msg)));
                    }
                    Err(e) => {
                        tracing::error!("Mount task panicked: {}", e);
                        unlock_result.set(Some(Err("Internal error occurred".to_string())));
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
                class: "vault-detail-header",

                // Icon container
                div {
                    class: "{status_icon_class}",
                    span {
                        class: "icon-container w-full h-full",
                        Icon { name: status_icon_name, size: IconSize(36) }
                    }
                }

                div {
                    class: "flex-1 min-w-0",
                    h2 {
                        class: "vault-detail-title",
                        "{vault.config.name}"
                    }
                    p {
                        class: "vault-detail-path",
                        "{vault.config.path.display()}"
                    }
                }

                // Ellipsis menu button (top-right)
                {
                    let is_mounted = matches!(vault.state, VaultState::Mounted { .. });
                    let vault_id_for_stats = vault_id.clone();
                    let vault_name_for_stats = vault_name.clone();
                    rsx! {
                        div {
                            class: "relative",

                            // Ellipsis button
                            button {
                                class: "btn-ellipsis",
                                title: "More options",
                                onclick: move |_| show_dropdown.set(!show_dropdown()),
                                span {
                                    class: "icon-container w-5 h-5",
                                    Icon { name: IconName::EllipsisVertical, size: IconSize(20) }
                                }
                            }

                            // Dropdown menu
                            if show_dropdown() {
                                DropdownMenu {
                                    show_stats: is_mounted,
                                    on_stats: if is_mounted {
                                        Some(EventHandler::new(move |_| {
                                            open_stats_window(vault_id_for_stats.clone(), vault_name_for_stats.clone());
                                        }))
                                    } else {
                                        None
                                    },
                                    on_change_password: move |_| show_change_password.set(true),
                                    on_remove: move |_| show_remove_confirm.set(true),
                                    on_close: move |_| show_dropdown.set(false),
                                }
                            }
                        }
                    }
                }
            }

            // Combined status + actions section
            div {
                class: "vault-detail-section",

                // Status row with backend badge at top-right
                div {
                    class: "flex items-center justify-between mb-6",

                    // Status indicator + mount path
                    div {
                        class: "flex items-center gap-2",

                        match &vault.state {
                            VaultState::Mounted { mountpoint } => {
                                rsx! {
                                    span { class: "status-mounted", "Mounted" }
                                    span {
                                        class: "text-sm text-secondary",
                                        "at {mountpoint.display()}"
                                    }
                                }
                            }
                            VaultState::Locked => {
                                rsx! {
                                    span { class: "status-locked", "Locked" }
                                }
                            }
                        }
                    }

                    // Backend badge (top-right) - clickable to change backend
                    {
                        let backend = vault.config.preferred_backend;
                        let badge_class = match backend {
                            crate::state::BackendType::Fuse => "badge-backend badge-backend-fuse",
                            crate::state::BackendType::FSKit => "badge-backend badge-backend-fskit",
                            crate::state::BackendType::WebDav => "badge-backend badge-backend-webdav",
                            crate::state::BackendType::Nfs => "badge-backend badge-backend-nfs",
                        };
                        let tooltip = match backend {
                            crate::state::BackendType::Fuse => "FUSE: Kernel-based filesystem via macFUSE. Click to change.",
                            crate::state::BackendType::FSKit => "FSKit: Native macOS filesystem (15.4+). Click to change.",
                            crate::state::BackendType::WebDav => "WebDAV: Network-based access via local server. Click to change.",
                            crate::state::BackendType::Nfs => "NFS: Network filesystem via local server. Click to change.",
                        };
                        rsx! {
                            button {
                                class: "{badge_class}",
                                title: "{tooltip}",
                                onclick: move |_| show_backend_dialog.set(true),
                                "{backend.display_name()}"
                            }
                        }
                    }
                }

                // Action buttons
                match &vault.state {
                    VaultState::Locked => {
                        rsx! {
                            ActionButton {
                                label: "Unlock Vault",
                                icon: IconName::LockOpen,
                                onclick: move |_| {
                                    unlock_result.set(None);
                                    show_unlock_dialog.set(true);
                                },
                            }
                        }
                    },
                    VaultState::Mounted { mountpoint } => {
                        let mp = mountpoint.clone();
                        let mp_for_reveal = mp.clone();
                        let id_for_unmount = vault_id.clone();
                        rsx! {
                            div { class: "flex flex-col gap-3",
                                ActionButton {
                                    label: "Reveal in Finder",
                                    icon: IconName::FolderOpen,
                                    onclick: move |_| {
                                        if let Err(e) = open::that(&mp_for_reveal) {
                                            tracing::error!("Failed to open {}: {}", mp_for_reveal.display(), e);
                                            error_state.set(Some(
                                                UserFacingError::new("Couldn't Open Vault", format!("Failed to open the vault location: {}", e))
                                                    .with_suggestion("The mount point may no longer exist. Try locking and unlocking the vault.")
                                            ));
                                        }
                                    },
                                }
                                ActionButton {
                                    label: "Lock Vault",
                                    icon: IconName::Lock,
                                    secondary: true,
                                    onclick: move |_| {
                                        let vault_id = id_for_unmount.clone();
                                        let vault_id_for_log = vault_id.clone();
                                        let vault_id_for_state = vault_id.clone();
                                        let mp_for_lsof = mp.clone();
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
                                                    let err_str = e.to_string().to_lowercase();
                                                    if err_str.contains("busy")
                                                        || err_str.contains("ebusy")
                                                        || err_str.contains("resource busy")
                                                        || err_str.contains("device busy")
                                                    {
                                                        tracing::warn!("Vault busy, showing force lock dialog: {}", e);
                                                        let procs = find_processes_using_mount(&mp_for_lsof);
                                                        blocking_processes.set(procs);
                                                        force_lock_error.set(e.to_string());
                                                        force_lock_context.set(ForceLockContext::Lock);
                                                        show_force_lock_dialog.set(true);
                                                    } else {
                                                        tracing::error!("Failed to unmount vault: {}", e);
                                                        error_state.set(Some(
                                                            UserFacingError::new("Couldn't Lock Vault", e.to_string())
                                                                .with_suggestion("Make sure no applications are using files in the vault and try again.")
                                                        ));
                                                    }
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
                        }
                    },
                }

                // Quick stats row (mounted only)
                if let VaultState::Mounted { .. } = &vault.state {
                    {
                        let vault_id_for_stats = vault_id.clone();
                        rsx! {
                            QuickStats { vault_id: vault_id_for_stats }
                        }
                    }
                }
            }
        }

        // Unlock/Mount dialog (rendered at root level for proper overlay)
        // Dialog manages its own visual state internally to prevent DOM diffing issues
        if show_unlock_dialog() {
            UnlockDialog {
                key: "{vault_id}-unlock-dialog",
                vault_name: vault_name.clone(),
                unlock_result: unlock_result(),
                on_unlock: handle_password_submit,
                on_cancel: move |_| {
                    show_unlock_dialog.set(false);
                    unlock_result.set(None);
                },
            }
        }

        // Backend selection dialog
        if show_backend_dialog() {
            {
                let vault_id_for_backend = vault_id.clone();
                let vault_id_for_unmount = vault_id.clone();
                let current_backend = vault.config.preferred_backend;
                let current_local_mode = vault.config.local_mode;
                let is_mounted = matches!(vault.state, VaultState::Mounted { .. });
                let mountpoint_for_lsof = match &vault.state {
                    VaultState::Mounted { mountpoint } => Some(mountpoint.clone()),
                    _ => None,
                };
                rsx! {
                    BackendDialog {
                        current_backend: current_backend,
                        local_mode: current_local_mode,
                        is_mounted: is_mounted,
                        on_select: move |settings: VaultMountSettings| {
                            // Update the vault's backend and local_mode settings
                            app_state.write().set_vault_mount_settings(&vault_id_for_backend, settings.backend, settings.local_mode);
                            // Save to disk
                            if let Err(e) = app_state.read().save() {
                                tracing::error!("Failed to save config: {}", e);
                            }
                            show_backend_dialog.set(false);
                        },
                        on_unmount_and_apply: move |settings: VaultMountSettings| {
                            let vault_id = vault_id_for_unmount.clone();
                            let vault_id_for_log = vault_id.clone();
                            let vault_id_for_state = vault_id.clone();
                            let vault_id_for_settings_update = vault_id.clone();
                            let mp_for_lsof = mountpoint_for_lsof.clone();
                            show_backend_dialog.set(false);
                            spawn(async move {
                                // First update the backend and local_mode config
                                app_state.write().set_vault_mount_settings(&vault_id_for_settings_update, settings.backend, settings.local_mode);
                                if let Err(e) = app_state.read().save() {
                                    tracing::error!("Failed to save config: {}", e);
                                }

                                // Then unmount
                                let manager = mount_manager();
                                let result = tokio::task::spawn_blocking(move || {
                                    manager.unmount(&vault_id)
                                }).await;

                                match result {
                                    Ok(Ok(())) => {
                                        tracing::info!("Vault {} unmounted after settings change", vault_id_for_log);
                                        app_state.write().set_vault_state(&vault_id_for_state, VaultState::Locked);
                                    }
                                    Ok(Err(e)) => {
                                        let err_str = e.to_string().to_lowercase();
                                        // Check if it's a "busy" error that might benefit from force unmount
                                        if err_str.contains("busy")
                                            || err_str.contains("ebusy")
                                            || err_str.contains("resource busy")
                                            || err_str.contains("device busy")
                                        {
                                            tracing::warn!("Vault busy during settings change, showing force lock dialog: {}", e);
                                            // Get processes using the mount
                                            if let Some(mp) = &mp_for_lsof {
                                                let procs = find_processes_using_mount(mp);
                                                blocking_processes.set(procs);
                                            }
                                            force_lock_error.set(e.to_string());
                                            force_lock_context.set(ForceLockContext::BackendChange);
                                            show_force_lock_dialog.set(true);
                                        } else {
                                            tracing::error!("Failed to unmount vault: {}", e);
                                            error_state.set(Some(
                                                UserFacingError::new("Couldn't Unmount Vault", e.to_string())
                                                    .with_suggestion("The settings were changed but the vault couldn't be unmounted. Try locking it manually.")
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Unmount task panicked: {}", e);
                                        error_state.set(Some(
                                            UserFacingError::new("Internal Error", "An unexpected error occurred while unmounting the vault.")
                                                .with_technical(e.to_string())
                                        ));
                                    }
                                }
                            });
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

        // Force lock dialog
        if show_force_lock_dialog() {
            {
                let vault_id_for_force = vault_id.clone();
                let vault_id_for_retry = vault_id.clone();
                let vault_name_for_dialog = vault_name.clone();
                rsx! {
                    ForceLockDialog {
                        vault_name: vault_name_for_dialog,
                        error_message: force_lock_error(),
                        processes: blocking_processes(),
                        on_retry: move |_| {
                            // Close dialog and retry normal unmount
                            show_force_lock_dialog.set(false);
                            let vault_id = vault_id_for_retry.clone();
                            let vault_id_for_log = vault_id.clone();
                            let vault_id_for_state = vault_id.clone();
                            spawn(async move {
                                let manager = mount_manager();
                                let result = tokio::task::spawn_blocking(move || {
                                    manager.unmount(&vault_id)
                                }).await;

                                match result {
                                    Ok(Ok(())) => {
                                        tracing::info!("Vault {} unmounted on retry", vault_id_for_log);
                                        app_state.write().set_vault_state(&vault_id_for_state, VaultState::Locked);
                                    }
                                    Ok(Err(e)) => {
                                        tracing::error!("Retry unmount failed: {}", e);
                                        error_state.set(Some(
                                            UserFacingError::new("Couldn't Lock Vault", e.to_string())
                                                .with_suggestion("Close all applications using the vault and try again, or use Force Lock.")
                                        ));
                                    }
                                    Err(e) => {
                                        tracing::error!("Retry unmount task panicked: {}", e);
                                        error_state.set(Some(
                                            UserFacingError::new("Internal Error", "An unexpected error occurred.")
                                                .with_technical(e.to_string())
                                        ));
                                    }
                                }
                            });
                        },
                        on_force: move |_| {
                            // Force unmount the vault
                            show_force_lock_dialog.set(false);
                            let vault_id = vault_id_for_force.clone();
                            let vault_id_for_log = vault_id.clone();
                            let vault_id_for_state = vault_id.clone();
                            let context = force_lock_context();
                            spawn(async move {
                                let manager = mount_manager();
                                let result = tokio::task::spawn_blocking(move || {
                                    manager.force_unmount(&vault_id)
                                }).await;

                                match result {
                                    Ok(Ok(())) => {
                                        let action = match context {
                                            ForceLockContext::Lock => "force locked",
                                            ForceLockContext::BackendChange => "force unmounted for backend change",
                                        };
                                        tracing::info!("Vault {} {}", vault_id_for_log, action);
                                        app_state.write().set_vault_state(&vault_id_for_state, VaultState::Locked);
                                    }
                                    Ok(Err(e)) => {
                                        tracing::error!("Force unmount failed: {}", e);
                                        error_state.set(Some(
                                            UserFacingError::new("Force Lock Failed", e.to_string())
                                                .with_suggestion("The vault could not be force locked. You may need to close applications manually or restart your computer.")
                                        ));
                                    }
                                    Err(e) => {
                                        tracing::error!("Force unmount task panicked: {}", e);
                                        error_state.set(Some(
                                            UserFacingError::new("Internal Error", "An unexpected error occurred.")
                                                .with_technical(e.to_string())
                                        ));
                                    }
                                }
                            });
                        },
                        on_cancel: move |_| {
                            show_force_lock_dialog.set(false);
                        },
                    }
                }
            }
        }
    }
}

/// Unified action button - primary (colored) or secondary (outlined)
#[component]
fn ActionButton(
    label: &'static str,
    icon: IconName,
    onclick: EventHandler<()>,
    #[props(default = false)] secondary: bool,
) -> Element {
    let class = if secondary { "btn-action btn-action-secondary" } else { "btn-action btn-action-primary" };
    rsx! {
        button {
            class: "{class}",
            onclick: move |_| onclick.call(()),
            span { class: "icon-container w-5 h-5", Icon { name: icon, size: IconSize(18) } }
            span { "{label}" }
        }
    }
}

/// Dropdown menu for secondary actions
#[component]
fn DropdownMenu(
    show_stats: bool,
    on_stats: Option<EventHandler<()>>,
    on_change_password: EventHandler<()>,
    on_remove: EventHandler<()>,
    on_close: EventHandler<()>,
) -> Element {
    rsx! {
        // Click catcher to close dropdown when clicking outside
        div {
            class: "fixed inset-0 z-40",
            onclick: move |_| on_close.call(()),
        }

        // Dropdown menu
        div {
            class: "dropdown-menu",

            // Statistics (only when mounted)
            if show_stats {
                if let Some(stats_handler) = on_stats {
                    button {
                        class: "dropdown-item",
                        onclick: move |_| {
                            stats_handler.call(());
                            on_close.call(());
                        },
                        span { class: "icon-container w-4 h-4", Icon { name: IconName::ChartBar, size: IconSize(16) } }
                        span { "View Statistics" }
                    }
                }
            }

            // Change Password
            button {
                class: "dropdown-item",
                onclick: move |_| {
                    on_change_password.call(());
                    on_close.call(());
                },
                span { class: "icon-container w-4 h-4", Icon { name: IconName::Key, size: IconSize(16) } }
                span { "Change Password" }
            }

            // Divider
            div { class: "dropdown-divider" }

            // Remove (danger)
            button {
                class: "dropdown-item dropdown-item-danger",
                onclick: move |_| {
                    on_remove.call(());
                    on_close.call(());
                },
                span { class: "icon-container w-4 h-4", Icon { name: IconName::Trash, size: IconSize(16) } }
                span { "Remove from List" }
            }
        }
    }
}

/// Quick stats row for mounted vaults - shows session totals
#[component]
fn QuickStats(vault_id: String) -> Element {
    // Auto-refresh stats every second
    let mut refresh_counter = use_signal(|| 0u32);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            refresh_counter.with_mut(|c| *c = c.wrapping_add(1));
        }
    });

    let _ = refresh_counter();

    let stats = mount_manager().get_stats(&vault_id);

    match stats {
        Some(stats) => {
            let read_str = format_bytes(stats.bytes_read());
            let write_str = format_bytes(stats.bytes_written());

            rsx! {
                div {
                    class: "quick-stats",
                    span { class: "quick-stats-item", "↓ {read_str}" }
                    span { class: "quick-stats-separator", "·" }
                    span { class: "quick-stats-item", "↑ {write_str}" }
                }
            }
        }
        None => rsx! {},
    }
}
