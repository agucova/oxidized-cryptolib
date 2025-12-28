//! Dialog components for vault operations
//!
//! These dialogs handle user interactions like unlocking, creating, and
//! configuring vaults.

mod add_vault_dialog;
mod backend_dialog;
mod confirm_dialog;
mod create_vault_dialog;
mod error_dialog;
mod settings_dialog;
mod unlock_dialog;

#[cfg(all(target_os = "macos", feature = "fskit"))]
mod fskit_setup_dialog;

pub use add_vault_dialog::AddVaultDialog;
pub use backend_dialog::BackendDialog;
pub use confirm_dialog::ConfirmDialog;
pub use create_vault_dialog::CreateVaultDialog;
pub use error_dialog::ErrorDialog;
pub use settings_dialog::SettingsDialog;
pub use unlock_dialog::{UnlockDialog, UnlockState};

#[cfg(all(target_os = "macos", feature = "fskit"))]
pub use fskit_setup_dialog::FSKitSetupDialog;

// TODO: Phase 5 - Implement password change dialog
// mod change_password;
// pub use change_password::ChangePasswordDialog;
