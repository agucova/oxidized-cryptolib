//! Main application component and layout

use dioxus::prelude::*;

use crate::backend::{cleanup_and_exit, mount_manager};
use crate::components::{EmptyState, Sidebar, VaultDetail};
use crate::dialogs::{AddVaultDialog, CreateVaultDialog};
use crate::menu::MenuBarEvent;
use crate::state::{use_app_state, AppState, VaultConfig, VaultState};
use crate::tray::menu::VaultAction;
use crate::tray::{update_tray_menu, TrayEvent};
use crate::windows::{SettingsWindow, StatsWindow, StatsWindowProps};

#[cfg(all(target_os = "macos", feature = "fskit"))]
use crate::dialogs::FSKitSetupDialog;

/// Tailwind CSS stylesheet asset
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

/// Root application component
#[component]
pub fn App() -> Element {
    // Initialize application state
    let _app_state = use_context_provider(|| Signal::new(AppState::load()));
    let mut app_state = use_app_state();
    let mut selected_vault = use_signal(|| None::<String>);
    let mut show_add_vault_dialog = use_signal(|| false);
    let mut show_create_vault_dialog = use_signal(|| false);

    // Get theme and platform classes for styling
    let theme_class = app_state.read().config.theme.css_class().unwrap_or("");
    let platform_class = crate::current_platform().css_class();
    let root_class = format!("app-root {} {}", theme_class, platform_class);

    rsx! {
        // Include Tailwind CSS
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }

        // Main two-panel layout
        div {
            class: "{root_class}",

            // Left sidebar with vault list
            Sidebar {
                selected_vault_id: selected_vault(),
                on_select: move |id: String| selected_vault.set(Some(id)),
                on_add_vault: move |_| show_add_vault_dialog.set(true),
                on_new_vault: move |_| show_create_vault_dialog.set(true),
                on_settings: move |_| open_settings_window(),
            }

            // Right panel with vault details or empty state
            div {
                class: "content-panel",

                if let Some(vault_id) = selected_vault() {
                    VaultDetail {
                        vault_id,
                        on_removed: move |_| selected_vault.set(None),
                    }
                } else {
                    EmptyState {}
                }
            }
        }

        // Add existing vault dialog
        if show_add_vault_dialog() {
            AddVaultDialog {
                on_complete: move |_| show_add_vault_dialog.set(false),
                on_cancel: move |_| show_add_vault_dialog.set(false),
            }
        }

        // Create new vault wizard
        if show_create_vault_dialog() {
            CreateVaultDialog {
                on_complete: move |path: std::path::PathBuf| {
                    // Add the newly created vault to state
                    let name = path
                        .file_name()
                        .map(|n: &std::ffi::OsStr| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "New Vault".to_string());
                    // Use the default backend from settings
                    let default_backend = app_state.read().config.default_backend;
                    let config = VaultConfig::with_backend(name, path, default_backend);
                    let id = config.id.clone();
                    app_state.write().add_vault(config);
                    selected_vault.set(Some(id));
                    show_create_vault_dialog.set(false);
                },
                on_cancel: move |_| show_create_vault_dialog.set(false),
            }
        }

        // FSKit setup wizard (macOS only, conditionally compiled)
        FSKitSetupWrapper {}

        // Tray event handler
        TrayEventHandler {
            on_select_vault: move |id: String| selected_vault.set(Some(id)),
        }

        // Menu bar event handler
        MenuEventHandler {
            on_add_vault: move |_| show_add_vault_dialog.set(true),
            on_new_vault: move |_| show_create_vault_dialog.set(true),
        }

        // Tray menu updater - keeps tray menu in sync with vault state
        TrayMenuUpdater {}
    }
}

/// Open the settings window in a separate window
fn open_settings_window() {
    let window = dioxus::desktop::window();
    let dom = VirtualDom::new(SettingsWindow);
    // Build a menu for this window to maintain consistent menu bar
    let menu = crate::menu::build_menu_bar();
    let cfg = dioxus::desktop::Config::new()
        .with_window(
            dioxus::desktop::WindowBuilder::new()
                .with_title("Settings")
                .with_inner_size(dioxus::desktop::LogicalSize::new(580.0, 620.0))
                .with_min_inner_size(dioxus::desktop::LogicalSize::new(480.0, 500.0))
                .with_resizable(true),
        )
        .with_menu(menu);
    window.new_window(dom, cfg);
}

/// Open the statistics window for a vault in a separate window
pub fn open_stats_window(vault_id: String, vault_name: String) {
    let window = dioxus::desktop::window();
    let props = StatsWindowProps { vault_id, vault_name: vault_name.clone() };
    let dom = VirtualDom::new_with_props(StatsWindow, props);
    // Build a menu for this window to maintain consistent menu bar
    let menu = crate::menu::build_menu_bar();
    // Include CSS in head - workaround for asset loading in secondary windows with props
    let css_path = asset!("/assets/tailwind.css");
    let custom_head = format!(r#"<link rel="stylesheet" href="{}" />"#, css_path);
    let cfg = dioxus::desktop::Config::new()
        .with_window(
            dioxus::desktop::WindowBuilder::new()
                .with_title(format!("Statistics - {}", vault_name))
                .with_inner_size(dioxus::desktop::LogicalSize::new(500.0, 700.0))
                .with_min_inner_size(dioxus::desktop::LogicalSize::new(420.0, 550.0))
                .with_resizable(true),
        )
        .with_custom_head(custom_head)
        .with_menu(menu);
    window.new_window(dom, cfg);
}

/// Wrapper component for FSKit setup dialog
///
/// This is a separate component so we can use #[cfg] attributes properly
/// (rsx! macro doesn't support inline #[cfg]).
#[cfg(all(target_os = "macos", feature = "fskit"))]
#[component]
fn FSKitSetupWrapper() -> Element {
    let mut app_state = use_app_state();
    let mut show_fskit_setup = use_signal(|| false);

    // Check FSKit status on startup
    let config_dismissed = app_state.read().config.fskit_setup_dismissed;
    use_effect(move || {
        if config_dismissed {
            return;
        }
        spawn(async move {
            use oxidized_fskit::setup::{get_status, BridgeStatus};
            let status = get_status().await;
            // Show dialog if FSKit needs setup (but is supported)
            if matches!(
                status,
                BridgeStatus::NotInstalled
                    | BridgeStatus::Quarantined
                    | BridgeStatus::ExtensionDisabled
            ) {
                show_fskit_setup.set(true);
            }
        });
    });

    if show_fskit_setup() {
        rsx! {
            FSKitSetupDialog {
                on_complete: move |_| {
                    show_fskit_setup.set(false);
                },
                on_dismiss: move |_| {
                    // Mark as dismissed so we don't show again
                    app_state.write().config.fskit_setup_dismissed = true;
                    let _ = app_state.read().save();
                    show_fskit_setup.set(false);
                },
            }
        }
    } else {
        rsx! {}
    }
}

/// No-op wrapper for non-macOS or non-fskit builds
#[cfg(not(all(target_os = "macos", feature = "fskit")))]
#[component]
fn FSKitSetupWrapper() -> Element {
    rsx! {}
}

/// Component that handles tray menu events
#[component]
fn TrayEventHandler(on_select_vault: EventHandler<String>) -> Element {
    let mut app_state = use_app_state();

    // Poll for tray events
    use_effect(move || {
        // Set up a timer to poll for tray events
        spawn(async move {
            loop {
                // Check for tray events
                if let Some(receiver) = crate::tray_receiver() {
                    while let Ok(event) = receiver.try_recv() {
                        handle_tray_event(event, &mut app_state, &on_select_vault);
                    }
                }
                // Wait a bit before polling again
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
    });

    rsx! {}
}

/// Handle a single tray event
fn handle_tray_event(
    event: TrayEvent,
    app_state: &mut Signal<AppState>,
    on_select_vault: &EventHandler<String>,
) {
    match event {
        TrayEvent::ShowHide => {
            // Toggle window visibility
            let window = dioxus::desktop::window();
            if window.is_visible() {
                window.set_visible(false);
            } else {
                window.set_visible(true);
                window.set_focus();
            }
        }
        TrayEvent::Settings => {
            // Open settings in a new window
            open_settings_window();
        }
        TrayEvent::Vault(action) => {
            handle_vault_action(action, app_state, on_select_vault);
        }
        TrayEvent::Quit => {
            cleanup_and_exit();
        }
    }
}

/// Handle a vault-specific action from the tray
fn handle_vault_action(
    action: VaultAction,
    app_state: &mut Signal<AppState>,
    on_select_vault: &EventHandler<String>,
) {
    match action {
        VaultAction::Unlock(vault_id) => {
            // Show the main window and select this vault to prompt for unlock
            let window = dioxus::desktop::window();
            window.set_visible(true);
            window.set_focus();
            on_select_vault.call(vault_id);
        }
        VaultAction::Lock(vault_id) => {
            // Unmount the vault
            let vault_id_clone = vault_id.clone();
            let mut app_state = *app_state;
            spawn(async move {
                let manager = mount_manager();
                let result = tokio::task::spawn_blocking(move || manager.unmount(&vault_id)).await;

                match result {
                    Ok(Ok(())) => {
                        tracing::info!("Vault {} locked via tray", vault_id_clone);
                        app_state.write().set_vault_state(&vault_id_clone, VaultState::Locked);
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Failed to lock vault via tray: {}", e);
                    }
                    Err(e) => {
                        tracing::error!("Lock task panicked: {}", e);
                    }
                }
            });
        }
        VaultAction::ForceLock(vault_id) => {
            // Force unmount the vault
            let vault_id_clone = vault_id.clone();
            let mut app_state = *app_state;
            spawn(async move {
                let manager = mount_manager();
                let result =
                    tokio::task::spawn_blocking(move || manager.force_unmount(&vault_id)).await;

                match result {
                    Ok(Ok(())) => {
                        tracing::info!("Vault {} force locked via tray", vault_id_clone);
                        app_state.write().set_vault_state(&vault_id_clone, VaultState::Locked);
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Failed to force lock vault via tray: {}", e);
                    }
                    Err(e) => {
                        tracing::error!("Force lock task panicked: {}", e);
                    }
                }
            });
        }
        VaultAction::Reveal(vault_id) => {
            // Open the vault location in file manager
            if let Some(vault) = app_state.read().get_vault(&vault_id) {
                let path_to_reveal = match &vault.state {
                    VaultState::Mounted { mountpoint } => mountpoint.clone(),
                    VaultState::Locked => vault.config.path.clone(),
                };
                if let Err(e) = open::that(&path_to_reveal) {
                    tracing::error!("Failed to reveal vault at {}: {}", path_to_reveal.display(), e);
                }
            }
        }
    }
}

/// Component that keeps the tray menu in sync with vault state
///
/// Watches the app state and updates the tray menu whenever vaults change.
#[component]
fn TrayMenuUpdater() -> Element {
    let app_state = use_app_state();

    // Update tray menu whenever vault state changes
    use_effect(move || {
        let vaults = app_state.read().vaults();
        let window = dioxus::desktop::window();
        let visible = window.is_visible();
        update_tray_menu(&vaults, visible);
    });

    rsx! {}
}

/// Component that handles menu bar events
#[component]
fn MenuEventHandler(on_add_vault: EventHandler<()>, on_new_vault: EventHandler<()>) -> Element {
    // Poll for menu events
    use_effect(move || {
        spawn(async move {
            loop {
                // Check for menu events
                if let Some(receiver) = crate::menu_receiver() {
                    while let Ok(event) = receiver.try_recv() {
                        handle_menu_event(event, &on_add_vault, &on_new_vault);
                    }
                }
                // Wait a bit before polling again
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
    });

    rsx! {}
}

/// Handle a single menu bar event
fn handle_menu_event(
    event: MenuBarEvent,
    on_add_vault: &EventHandler<()>,
    on_new_vault: &EventHandler<()>,
) {
    match event {
        MenuBarEvent::AddVault => {
            let window = dioxus::desktop::window();
            window.set_visible(true);
            window.set_focus();
            on_add_vault.call(());
        }
        MenuBarEvent::NewVault => {
            let window = dioxus::desktop::window();
            window.set_visible(true);
            window.set_focus();
            on_new_vault.call(());
        }
        MenuBarEvent::CloseWindow => {
            let window = dioxus::desktop::window();
            window.set_visible(false);
        }
        MenuBarEvent::Preferences => {
            // Open settings in a new window
            open_settings_window();
        }
        MenuBarEvent::Refresh => {
            // Trigger a UI refresh - currently a no-op since Dioxus handles reactivity
            tracing::debug!("Menu: Refresh triggered");
        }
        MenuBarEvent::Documentation => {
            let _ = open::that("https://github.com/agucova/oxidized-cryptolib#readme");
        }
        MenuBarEvent::ReportIssue => {
            let _ = open::that("https://github.com/agucova/oxidized-cryptolib/issues/new");
        }
        // Vault-specific actions would need the selected vault ID
        // For now, these are handled via the VaultDetail panel
        MenuBarEvent::UnlockVault
        | MenuBarEvent::LockVault
        | MenuBarEvent::RevealVault
        | MenuBarEvent::ChangePassword
        | MenuBarEvent::ChangeBackend
        | MenuBarEvent::RemoveVault => {
            tracing::debug!("Menu: Vault action {:?} - handled via VaultDetail", event);
        }
        // Window actions are handled by the system
        MenuBarEvent::Minimize | MenuBarEvent::Zoom => {}
        // Standard macOS items (About and Quit handled by system)
        MenuBarEvent::About | MenuBarEvent::Quit => {}
    }
}
