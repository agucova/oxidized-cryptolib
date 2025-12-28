//! Error handling and user-friendly error display
//!
//! Maps internal error types to user-facing messages with suggestions
//! for resolution.

// TODO: Phase 6 - Implement error display
// mod display;
// pub use display::{UserFacingError, ErrorDisplay};

use thiserror::Error;

/// Errors that can occur during GUI operations
#[derive(Debug, Error)]
pub enum GuiError {
    #[error("Failed to unlock vault: {0}")]
    UnlockFailed(String),

    #[error("Failed to mount vault: {0}")]
    MountFailed(String),

    #[error("Failed to unmount vault: {0}")]
    UnmountFailed(String),

    #[error("Configuration error: {0}")]
    Config(#[from] crate::state::config::ConfigError),

    #[error("Vault not found: {0}")]
    VaultNotFound(String),
}

/// A user-friendly error with context and suggestions
#[derive(Debug, Clone)]
pub struct UserFacingError {
    /// Short title for the error
    pub title: String,
    /// Detailed description of what went wrong
    pub message: String,
    /// Suggestion for how to resolve the error
    pub suggestion: Option<String>,
    /// Technical details for advanced users
    pub technical_details: Option<String>,
}

impl UserFacingError {
    /// Create a new user-facing error
    pub fn new(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            suggestion: None,
            technical_details: None,
        }
    }

    /// Add a suggestion for resolution
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    /// Add technical details
    pub fn with_technical(mut self, details: impl Into<String>) -> Self {
        self.technical_details = Some(details.into());
        self
    }
}

impl From<GuiError> for UserFacingError {
    fn from(error: GuiError) -> Self {
        match error {
            GuiError::UnlockFailed(msg) => UserFacingError::new("Couldn't Unlock Vault", msg)
                .with_suggestion("Check your password and try again."),

            GuiError::MountFailed(msg) => UserFacingError::new("Couldn't Mount Vault", msg)
                .with_suggestion("Make sure FUSE is installed and try again."),

            GuiError::UnmountFailed(msg) => {
                UserFacingError::new("Couldn't Unmount Vault", msg).with_suggestion(
                    "Make sure no applications are using files in the vault and try again.",
                )
            }

            GuiError::Config(e) => UserFacingError::new("Configuration Error", e.to_string())
                .with_suggestion("Try resetting your configuration."),

            GuiError::VaultNotFound(path) => UserFacingError::new(
                "Vault Not Found",
                format!("The vault at {} could not be found.", path),
            )
            .with_suggestion("The vault may have been moved or deleted."),
        }
    }
}
