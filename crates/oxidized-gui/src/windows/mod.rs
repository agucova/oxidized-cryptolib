//! Secondary window components
//!
//! These are standalone windows that run in separate VirtualDom instances.

mod settings_window;
mod stats_window;

pub use settings_window::SettingsWindow;
pub use stats_window::{StatsWindow, StatsWindowProps};
