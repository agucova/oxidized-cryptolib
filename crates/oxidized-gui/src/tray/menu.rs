//! Tray menu building utilities
//!
//! Constructs the system tray menu based on current vault states.

use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};

use crate::state::{ManagedVault, VaultState};

/// Menu item IDs for identification
pub mod ids {
    pub const SHOW_HIDE: &str = "show_hide";
    pub const SETTINGS: &str = "settings";
    pub const QUIT: &str = "quit";

    /// Generate vault-specific menu item ID
    pub fn vault_unlock(vault_id: &str) -> String {
        format!("vault_unlock_{}", vault_id)
    }

    pub fn vault_lock(vault_id: &str) -> String {
        format!("vault_lock_{}", vault_id)
    }

    pub fn vault_reveal(vault_id: &str) -> String {
        format!("vault_reveal_{}", vault_id)
    }

    /// Parse a vault action from menu item ID
    pub fn parse_vault_action(id: &str) -> Option<super::VaultAction> {
        if let Some(vault_id) = id.strip_prefix("vault_unlock_") {
            Some(super::VaultAction::Unlock(vault_id.to_string()))
        } else if let Some(vault_id) = id.strip_prefix("vault_lock_") {
            Some(super::VaultAction::Lock(vault_id.to_string()))
        } else if let Some(vault_id) = id.strip_prefix("vault_reveal_") {
            Some(super::VaultAction::Reveal(vault_id.to_string()))
        } else {
            None
        }
    }
}

/// Actions that can be triggered from the tray menu
#[derive(Debug, Clone, PartialEq)]
pub enum VaultAction {
    Unlock(String),
    Lock(String),
    Reveal(String),
}

/// Events from the tray menu
#[derive(Debug, Clone)]
pub enum TrayEvent {
    /// Toggle window visibility
    ShowHide,
    /// Open settings dialog
    Settings,
    /// Vault-specific action
    Vault(VaultAction),
    /// Quit the application
    Quit,
}

impl TrayEvent {
    /// Parse a menu event into a TrayEvent
    pub fn from_menu_event(event: &MenuEvent) -> Option<Self> {
        let id = event.id().0.as_str();
        match id {
            ids::SHOW_HIDE => Some(TrayEvent::ShowHide),
            ids::SETTINGS => Some(TrayEvent::Settings),
            ids::QUIT => Some(TrayEvent::Quit),
            _ => ids::parse_vault_action(id).map(TrayEvent::Vault),
        }
    }
}

/// Build the tray menu with current vault states
pub fn build_menu(vaults: &[ManagedVault], window_visible: bool) -> Menu {
    let menu = Menu::new();

    // Show/Hide window
    let show_hide_label = if window_visible {
        "Hide Window"
    } else {
        "Show Window"
    };
    let show_hide = MenuItem::with_id(ids::SHOW_HIDE, show_hide_label, true, None);
    let _ = menu.append(&show_hide);

    // Separator
    let _ = menu.append(&PredefinedMenuItem::separator());

    // Vaults submenu (if any vaults exist)
    if !vaults.is_empty() {
        let vaults_submenu = Submenu::new("Vaults", true);

        for vault in vaults {
            let vault_submenu = build_vault_submenu(vault);
            let _ = vaults_submenu.append(&vault_submenu);
        }

        let _ = menu.append(&vaults_submenu);
        let _ = menu.append(&PredefinedMenuItem::separator());
    }

    // Settings
    let settings = MenuItem::with_id(ids::SETTINGS, "Settings...", true, None);
    let _ = menu.append(&settings);

    // Separator
    let _ = menu.append(&PredefinedMenuItem::separator());

    // Quit
    let quit = MenuItem::with_id(ids::QUIT, "Quit Oxidized Vault", true, None);
    let _ = menu.append(&quit);

    menu
}

/// Build a submenu for a single vault
fn build_vault_submenu(vault: &ManagedVault) -> Submenu {
    let status_icon = match &vault.state {
        VaultState::Locked => "🔒",
        VaultState::Mounted { .. } => "📂",
    };

    let label = format!("{} {}", status_icon, vault.config.name);
    let submenu = Submenu::new(&label, true);

    match &vault.state {
        VaultState::Locked => {
            // Unlock option for locked vaults
            let unlock = MenuItem::with_id(
                ids::vault_unlock(&vault.config.id),
                "Unlock...",
                true,
                None,
            );
            let _ = submenu.append(&unlock);
        }
        VaultState::Mounted { mountpoint } => {
            // Reveal in Finder
            let reveal = MenuItem::with_id(
                ids::vault_reveal(&vault.config.id),
                "Reveal in Finder",
                true,
                None,
            );
            let _ = submenu.append(&reveal);

            // Status text (disabled)
            let status = MenuItem::new(
                format!("Mounted at {}", mountpoint.display()),
                false,
                None,
            );
            let _ = submenu.append(&status);

            // Separator
            let _ = submenu.append(&PredefinedMenuItem::separator());

            // Lock option
            let lock = MenuItem::with_id(ids::vault_lock(&vault.config.id), "Lock", true, None);
            let _ = submenu.append(&lock);
        }
    }

    submenu
}
