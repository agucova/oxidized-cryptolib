//! Dialog components for vault operations
//!
//! These dialogs handle user interactions like unlocking, creating, and
//! configuring vaults.

mod add_vault_dialog;
mod create_vault_dialog;
mod unlock_dialog;

pub use add_vault_dialog::AddVaultDialog;
pub use create_vault_dialog::CreateVaultDialog;
pub use unlock_dialog::{UnlockDialog, UnlockState};

// TODO: Phase 5 - Implement password change dialog
// mod change_password;
// pub use change_password::ChangePasswordDialog;

// TODO: Phase 6 - Implement error dialog
// mod error_dialog;
// pub use error_dialog::ErrorDialog;

// TODO: Phase 8 - Implement settings dialog
// mod settings_dialog;
// pub use settings_dialog::SettingsDialog;
