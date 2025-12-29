//! Application menu bar for native macOS experience
//!
//! Provides a native menu bar with standard macOS menus (File, Edit, Vault, Window, Help).
//! Uses Dioxus's built-in menu support via `window().set_menu()`.

use crossbeam_channel::{unbounded, Receiver, Sender};
use dioxus::desktop::muda::{
    AboutMetadata, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
    accelerator::{Accelerator, Code, Modifiers},
};
use std::sync::OnceLock;

/// Menu item IDs for identification
pub mod ids {
    // App menu
    pub const SETTINGS: &str = "app_settings";

    // File menu
    pub const ADD_VAULT: &str = "file_add_vault";
    pub const NEW_VAULT: &str = "file_new_vault";
    pub const CLOSE_WINDOW: &str = "file_close_window";

    // Vault menu (context-sensitive based on selected vault)
    pub const VAULT_UNLOCK: &str = "vault_unlock";
    pub const VAULT_LOCK: &str = "vault_lock";
    pub const VAULT_REVEAL: &str = "vault_reveal";
    pub const VAULT_CHANGE_PASSWORD: &str = "vault_change_password";
    pub const VAULT_CHANGE_BACKEND: &str = "vault_change_backend";
    pub const VAULT_REMOVE: &str = "vault_remove";

    // View menu
    pub const VIEW_REFRESH: &str = "view_refresh";

    // Window menu
    pub const WINDOW_MINIMIZE: &str = "window_minimize";
    pub const WINDOW_ZOOM: &str = "window_zoom";

    // Help menu
    pub const HELP_DOCUMENTATION: &str = "help_documentation";
    pub const HELP_REPORT_ISSUE: &str = "help_report_issue";
}

/// Events from the application menu
#[derive(Debug, Clone)]
pub enum MenuBarEvent {
    // File menu
    AddVault,
    NewVault,
    CloseWindow,

    // Vault menu
    UnlockVault,
    LockVault,
    RevealVault,
    ChangePassword,
    ChangeBackend,
    RemoveVault,

    // View menu
    Refresh,

    // Window menu
    Minimize,
    Zoom,

    // Help menu
    Documentation,
    ReportIssue,

    // Standard macOS items handled by system
    About,
    Preferences,
    Quit,
}

impl MenuBarEvent {
    /// Parse a menu event ID into a MenuBarEvent
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            ids::SETTINGS => Some(Self::Preferences),
            ids::ADD_VAULT => Some(Self::AddVault),
            ids::NEW_VAULT => Some(Self::NewVault),
            ids::CLOSE_WINDOW => Some(Self::CloseWindow),
            ids::VAULT_UNLOCK => Some(Self::UnlockVault),
            ids::VAULT_LOCK => Some(Self::LockVault),
            ids::VAULT_REVEAL => Some(Self::RevealVault),
            ids::VAULT_CHANGE_PASSWORD => Some(Self::ChangePassword),
            ids::VAULT_CHANGE_BACKEND => Some(Self::ChangeBackend),
            ids::VAULT_REMOVE => Some(Self::RemoveVault),
            ids::VIEW_REFRESH => Some(Self::Refresh),
            ids::WINDOW_MINIMIZE => Some(Self::Minimize),
            ids::WINDOW_ZOOM => Some(Self::Zoom),
            ids::HELP_DOCUMENTATION => Some(Self::Documentation),
            ids::HELP_REPORT_ISSUE => Some(Self::ReportIssue),
            _ => None,
        }
    }
}

/// Global event receiver (initialized once)
static MENU_RECEIVER: OnceLock<Receiver<MenuBarEvent>> = OnceLock::new();
static MENU_SENDER: OnceLock<Sender<MenuBarEvent>> = OnceLock::new();

/// Get the menu event receiver
pub fn menu_receiver() -> Option<&'static Receiver<MenuBarEvent>> {
    MENU_RECEIVER.get()
}

/// Initialize the menu event channel (call once at startup)
pub fn init_menu_events() {
    let (sender, receiver) = unbounded();
    let _ = MENU_SENDER.set(sender.clone());
    let _ = MENU_RECEIVER.set(receiver);

    // Set up the global menu event handler
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if let Some(menu_event) = MenuBarEvent::from_id(event.id().0.as_str()) {
            let _ = sender.send(menu_event);
        }
    }));
}

/// Build the complete menu bar structure
/// Call this inside a component and use window.set_menu() to attach it
pub fn build_menu_bar() -> Menu {
    let menu_bar = Menu::new();

    // App menu (macOS only)
    #[cfg(target_os = "macos")]
    {
        let app_menu = build_app_menu();
        let _ = menu_bar.append(&app_menu);
    }

    // File menu
    let file_menu = build_file_menu();
    let _ = menu_bar.append(&file_menu);

    // Edit menu (standard)
    let edit_menu = build_edit_menu();
    let _ = menu_bar.append(&edit_menu);

    // Vault menu
    let vault_menu = build_vault_menu();
    let _ = menu_bar.append(&vault_menu);

    // View menu
    let view_menu = build_view_menu();
    let _ = menu_bar.append(&view_menu);

    // Window menu
    let window_menu = build_window_menu();
    let _ = menu_bar.append(&window_menu);

    // Help menu
    let help_menu = build_help_menu();
    let _ = menu_bar.append(&help_menu);

    menu_bar
}

/// Build the macOS App menu
#[cfg(target_os = "macos")]
fn build_app_menu() -> Submenu {
    let app_menu = Submenu::new("Oxidized Vault", true);

    // About
    let about_metadata = AboutMetadata {
        name: Some("Oxidized Vault".to_string()),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        copyright: Some("MIT License".to_string()),
        ..Default::default()
    };
    let _ = app_menu.append(&PredefinedMenuItem::about(None, Some(about_metadata)));

    let _ = app_menu.append(&PredefinedMenuItem::separator());

    // Settings (Cmd+,) - standard macOS preferences location
    let settings = MenuItem::with_id(
        ids::SETTINGS,
        "Settings...",
        true,
        Some(Accelerator::new(Some(Modifiers::META), Code::Comma)),
    );
    let _ = app_menu.append(&settings);

    let _ = app_menu.append(&PredefinedMenuItem::separator());

    // Services submenu
    let _ = app_menu.append(&PredefinedMenuItem::services(None));

    let _ = app_menu.append(&PredefinedMenuItem::separator());

    let _ = app_menu.append(&PredefinedMenuItem::hide(None));
    let _ = app_menu.append(&PredefinedMenuItem::hide_others(None));
    let _ = app_menu.append(&PredefinedMenuItem::show_all(None));

    let _ = app_menu.append(&PredefinedMenuItem::separator());

    let _ = app_menu.append(&PredefinedMenuItem::quit(None));

    app_menu
}

/// Build the File menu
fn build_file_menu() -> Submenu {
    let file_menu = Submenu::new("File", true);

    // Add Existing Vault (Cmd+O)
    let add_vault = MenuItem::with_id(
        ids::ADD_VAULT,
        "Add Existing Vault...",
        true,
        Some(Accelerator::new(Some(Modifiers::META), Code::KeyO)),
    );
    let _ = file_menu.append(&add_vault);

    // New Vault (Cmd+N)
    let new_vault = MenuItem::with_id(
        ids::NEW_VAULT,
        "New Vault...",
        true,
        Some(Accelerator::new(Some(Modifiers::META), Code::KeyN)),
    );
    let _ = file_menu.append(&new_vault);

    let _ = file_menu.append(&PredefinedMenuItem::separator());

    // Close Window (Cmd+W)
    let close_window = MenuItem::with_id(
        ids::CLOSE_WINDOW,
        "Close Window",
        true,
        Some(Accelerator::new(Some(Modifiers::META), Code::KeyW)),
    );
    let _ = file_menu.append(&close_window);

    file_menu
}

/// Build the Edit menu (standard macOS edit menu)
fn build_edit_menu() -> Submenu {
    let edit_menu = Submenu::new("Edit", true);

    let _ = edit_menu.append(&PredefinedMenuItem::undo(None));
    let _ = edit_menu.append(&PredefinedMenuItem::redo(None));
    let _ = edit_menu.append(&PredefinedMenuItem::separator());
    let _ = edit_menu.append(&PredefinedMenuItem::cut(None));
    let _ = edit_menu.append(&PredefinedMenuItem::copy(None));
    let _ = edit_menu.append(&PredefinedMenuItem::paste(None));
    let _ = edit_menu.append(&PredefinedMenuItem::select_all(None));

    edit_menu
}

/// Build the Vault menu (context-sensitive based on selected vault)
fn build_vault_menu() -> Submenu {
    let vault_menu = Submenu::new("Vault", true);

    // Unlock (Cmd+U)
    let unlock = MenuItem::with_id(
        ids::VAULT_UNLOCK,
        "Unlock",
        true, // Enable so shortcuts work
        Some(Accelerator::new(Some(Modifiers::META), Code::KeyU)),
    );
    let _ = vault_menu.append(&unlock);

    // Lock (Cmd+L)
    let lock = MenuItem::with_id(
        ids::VAULT_LOCK,
        "Lock",
        true,
        Some(Accelerator::new(Some(Modifiers::META), Code::KeyL)),
    );
    let _ = vault_menu.append(&lock);

    let _ = vault_menu.append(&PredefinedMenuItem::separator());

    // Reveal in Finder (Cmd+Shift+R)
    let reveal = MenuItem::with_id(
        ids::VAULT_REVEAL,
        "Reveal in Finder",
        true,
        Some(Accelerator::new(
            Some(Modifiers::META | Modifiers::SHIFT),
            Code::KeyR,
        )),
    );
    let _ = vault_menu.append(&reveal);

    let _ = vault_menu.append(&PredefinedMenuItem::separator());

    // Change Password
    let change_password = MenuItem::with_id(
        ids::VAULT_CHANGE_PASSWORD,
        "Change Password...",
        true,
        None,
    );
    let _ = vault_menu.append(&change_password);

    // Change Backend
    let change_backend = MenuItem::with_id(
        ids::VAULT_CHANGE_BACKEND,
        "Change Mount Backend...",
        true,
        None,
    );
    let _ = vault_menu.append(&change_backend);

    let _ = vault_menu.append(&PredefinedMenuItem::separator());

    // Remove from List (Cmd+Backspace)
    let remove = MenuItem::with_id(
        ids::VAULT_REMOVE,
        "Remove from List",
        true,
        Some(Accelerator::new(Some(Modifiers::META), Code::Backspace)),
    );
    let _ = vault_menu.append(&remove);

    vault_menu
}

/// Build the View menu
fn build_view_menu() -> Submenu {
    let view_menu = Submenu::new("View", true);

    // Refresh (Cmd+R)
    let refresh = MenuItem::with_id(
        ids::VIEW_REFRESH,
        "Refresh",
        true,
        Some(Accelerator::new(Some(Modifiers::META), Code::KeyR)),
    );
    let _ = view_menu.append(&refresh);

    let _ = view_menu.append(&PredefinedMenuItem::separator());

    // Enter Full Screen (standard macOS)
    let _ = view_menu.append(&PredefinedMenuItem::fullscreen(None));

    view_menu
}

/// Build the Window menu
fn build_window_menu() -> Submenu {
    let window_menu = Submenu::new("Window", true);

    let _ = window_menu.append(&PredefinedMenuItem::minimize(None));
    let _ = window_menu.append(&PredefinedMenuItem::maximize(None));

    let _ = window_menu.append(&PredefinedMenuItem::separator());

    let _ = window_menu.append(&PredefinedMenuItem::bring_all_to_front(None));

    window_menu
}

/// Build the Help menu
fn build_help_menu() -> Submenu {
    let help_menu = Submenu::new("Help", true);

    // Documentation
    let docs = MenuItem::with_id(
        ids::HELP_DOCUMENTATION,
        "Oxidized Vault Documentation",
        true,
        None,
    );
    let _ = help_menu.append(&docs);

    let _ = help_menu.append(&PredefinedMenuItem::separator());

    // Report Issue
    let report = MenuItem::with_id(ids::HELP_REPORT_ISSUE, "Report an Issue...", true, None);
    let _ = help_menu.append(&report);

    help_menu
}
