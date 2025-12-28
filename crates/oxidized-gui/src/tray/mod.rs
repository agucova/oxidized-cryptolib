//! System tray integration
//!
//! Provides system tray icon and menu for background operation.

pub mod menu;

use crossbeam_channel::{Receiver, Sender};
use muda::MenuEvent;
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::state::ManagedVault;

pub use menu::TrayEvent;

/// Error type for tray operations
#[derive(Debug, thiserror::Error)]
pub enum TrayError {
    #[error("Failed to create tray icon: {0}")]
    IconCreation(String),
    #[error("Failed to build tray: {0}")]
    Build(#[from] tray_icon::Error),
    #[error("Menu error: {0}")]
    Menu(#[from] muda::Error),
}

/// Manages the system tray icon and menu
pub struct TrayManager {
    _tray_icon: TrayIcon,
    event_receiver: Receiver<TrayEvent>,
}

impl TrayManager {
    /// Create a new tray manager
    ///
    /// Must be called from the main thread before starting the event loop.
    pub fn new() -> Result<Self, TrayError> {
        // Create a simple icon (16x16 blue square)
        let icon = create_default_icon()?;

        // Create channel for tray events
        let (event_sender, event_receiver) = crossbeam_channel::unbounded();

        // Set up menu event handler
        let sender = event_sender.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if let Some(tray_event) = TrayEvent::from_menu_event(&event) {
                let _ = sender.send(tray_event);
            }
        }));

        // Build initial menu (empty vaults, window visible)
        let menu = menu::build_menu(&[], true);

        // Create the tray icon
        let tray_icon = TrayIconBuilder::new()
            .with_icon(icon)
            .with_tooltip("Oxidized Vault")
            .with_menu(Box::new(menu))
            .build()?;

        Ok(Self {
            _tray_icon: tray_icon,
            event_receiver,
        })
    }

    /// Get the event receiver for polling tray events
    pub fn event_receiver(&self) -> &Receiver<TrayEvent> {
        &self.event_receiver
    }

    /// Update the tray menu with current vault states
    pub fn update_menu(&self, vaults: &[ManagedVault], window_visible: bool) {
        let menu = menu::build_menu(vaults, window_visible);
        // Note: tray-icon doesn't support updating menu after creation in 0.19
        // This would require recreating the tray icon or using a different approach
        // For now, we'll rebuild when needed
        let _ = menu; // Menu built but can't be updated dynamically yet
    }
}

/// Create a default tray icon
fn create_default_icon() -> Result<Icon, TrayError> {
    // Create a simple 32x32 icon with a lock symbol appearance
    // Using RGBA format (4 bytes per pixel)
    const SIZE: usize = 32;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];

    // Draw a simple blue circle with a white lock outline
    let center = SIZE as f32 / 2.0;
    let radius = SIZE as f32 / 2.0 - 2.0;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let idx = (y * SIZE + x) * 4;
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();

            if dist <= radius {
                // Blue color for the circle
                rgba[idx] = 33;      // R
                rgba[idx + 1] = 150; // G
                rgba[idx + 2] = 243; // B
                rgba[idx + 3] = 255; // A
            }
        }
    }

    // Draw a simple lock shape (white)
    // Lock body (rectangle in lower half)
    for y in 16..26 {
        for x in 10..22 {
            let idx = (y * SIZE + x) * 4;
            rgba[idx] = 255;     // R
            rgba[idx + 1] = 255; // G
            rgba[idx + 2] = 255; // B
            rgba[idx + 3] = 255; // A
        }
    }

    // Lock shackle (U shape in upper half)
    for y in 8..18 {
        for x in 12..20 {
            let is_shackle = (x >= 12 && x <= 14) || (x >= 17 && x <= 19) || (y >= 8 && y <= 10);
            if is_shackle {
                let idx = (y * SIZE + x) * 4;
                rgba[idx] = 255;     // R
                rgba[idx + 1] = 255; // G
                rgba[idx + 2] = 255; // B
                rgba[idx + 3] = 255; // A
            }
        }
    }

    Icon::from_rgba(rgba, SIZE as u32, SIZE as u32)
        .map_err(|e| TrayError::IconCreation(e.to_string()))
}

/// Global channel sender for tray events (used by TrayEventHandler component)
static TRAY_EVENT_SENDER: std::sync::OnceLock<Sender<TrayEvent>> = std::sync::OnceLock::new();

/// Initialize the tray event channel and return the receiver
///
/// This should be called once at startup before creating the TrayManager.
pub fn init_tray_channel() -> Receiver<TrayEvent> {
    let (sender, receiver) = crossbeam_channel::unbounded();
    let _ = TRAY_EVENT_SENDER.set(sender);
    receiver
}

/// Get the tray event sender (for use by TrayManager)
pub fn get_tray_sender() -> Option<&'static Sender<TrayEvent>> {
    TRAY_EVENT_SENDER.get()
}
