//! System tray integration
//!
//! Provides system tray icon and menu for background operation.
//!
//! The tray menu is dynamically updated when vaults are added, removed, or
//! change state (locked/mounted). Use [`update_tray_menu`] to refresh.

pub mod menu;

use std::cell::RefCell;

use crossbeam_channel::Receiver;
use muda::MenuEvent;
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::state::ManagedVault;

pub use menu::TrayEvent;

// Thread-local storage for the tray icon.
// TrayIcon is not Send/Sync on macOS (uses Rc<RefCell> internally),
// but all tray operations happen on the main thread anyway.
thread_local! {
    static TRAY_ICON: RefCell<Option<TrayIcon>> = const { RefCell::new(None) };
}

/// Update the tray menu with current vault states
///
/// Must be called from the main thread.
/// Returns `true` if the menu was updated, `false` if the tray isn't initialized.
pub fn update_tray_menu(vaults: &[ManagedVault], window_visible: bool) -> bool {
    TRAY_ICON.with(|tray_cell| {
        if let Some(ref tray) = *tray_cell.borrow() {
            let menu = menu::build_menu(vaults, window_visible);
            tray.set_menu(Some(Box::new(menu)));
            true
        } else {
            false
        }
    })
}

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

        // Store in thread-local for dynamic updates
        TRAY_ICON.with(|tray_cell| {
            *tray_cell.borrow_mut() = Some(tray_icon);
        });

        Ok(Self { event_receiver })
    }

    /// Get the event receiver for polling tray events
    pub fn event_receiver(&self) -> &Receiver<TrayEvent> {
        &self.event_receiver
    }
}

/// Create a default tray icon
///
/// Creates a 22x22 template-style icon (monochrome black) suitable for macOS menu bar.
/// On macOS, this will be used as a template icon that adapts to light/dark mode.
fn create_default_icon() -> Result<Icon, TrayError> {
    // 22x22 is the standard macOS menu bar icon size
    const SIZE: usize = 22;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];

    // Helper to set pixel with alpha (for antialiasing)
    // White color for dark menu bars (most common on macOS)
    let set_pixel = |rgba: &mut [u8], x: usize, y: usize, alpha: u8| {
        if x < SIZE && y < SIZE {
            let idx = (y * SIZE + x) * 4;
            rgba[idx] = 255;     // R
            rgba[idx + 1] = 255; // G
            rgba[idx + 2] = 255; // B
            rgba[idx + 3] = alpha; // A
        }
    };

    // Helper to blend pixel (for antialiasing)
    let blend_pixel = |rgba: &mut [u8], x: usize, y: usize, alpha: u8| {
        if x < SIZE && y < SIZE {
            let idx = (y * SIZE + x) * 4;
            let existing = rgba[idx + 3] as u16;
            let new_alpha = ((existing + alpha as u16).min(255)) as u8;
            rgba[idx] = 255;
            rgba[idx + 1] = 255;
            rgba[idx + 2] = 255;
            rgba[idx + 3] = new_alpha;
        }
    };

    // Draw lock body (rounded rectangle) - bottom portion
    // Body: x=5..17, y=10..19 with rounded corners
    let body_left = 5;
    let body_right = 16;
    let body_top = 10;
    let body_bottom = 18;
    let corner_radius = 2.0f32;

    for y in body_top..=body_bottom {
        for x in body_left..=body_right {
            let fx = x as f32;
            let fy = y as f32;

            // Check if we're in a corner region
            let in_corner = |cx: f32, cy: f32| -> f32 {
                let dx = fx - cx;
                let dy = fy - cy;
                let dist = (dx * dx + dy * dy).sqrt();
                if dist <= corner_radius {
                    255.0
                } else if dist <= corner_radius + 1.0 {
                    255.0 * (corner_radius + 1.0 - dist)
                } else {
                    0.0
                }
            };

            let alpha = if y == body_top && x == body_left {
                in_corner(body_left as f32 + corner_radius, body_top as f32 + corner_radius)
            } else if y == body_top && x == body_right {
                in_corner(body_right as f32 - corner_radius, body_top as f32 + corner_radius)
            } else if y == body_bottom && x == body_left {
                in_corner(body_left as f32 + corner_radius, body_bottom as f32 - corner_radius)
            } else if y == body_bottom && x == body_right {
                in_corner(body_right as f32 - corner_radius, body_bottom as f32 - corner_radius)
            } else {
                255.0
            };

            set_pixel(&mut rgba, x, y, alpha as u8);
        }
    }

    // Draw shackle (rounded U-shape at top)
    // Outer arc from x=6 to x=15, inner arc creates the U shape
    let shackle_outer_radius = 5.0f32;
    let shackle_inner_radius = 2.5f32;
    let shackle_center_x = 10.5f32;
    let shackle_center_y = 9.0f32;
    let stroke_width = 2.0f32;

    for y in 2..=11 {
        for x in 4..=17 {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;

            let dx = fx - shackle_center_x;
            let dy = fy - shackle_center_y;
            let dist = (dx * dx + dy * dy).sqrt();

            // Only draw the top half of the arc (y < center) plus the vertical legs
            if fy <= shackle_center_y {
                // Arc portion
                let outer_edge = shackle_outer_radius;
                let inner_edge = shackle_outer_radius - stroke_width;

                if dist >= inner_edge && dist <= outer_edge {
                    let alpha = if dist < inner_edge + 0.5 {
                        ((dist - inner_edge) * 2.0 * 255.0) as u8
                    } else if dist > outer_edge - 0.5 {
                        ((outer_edge - dist) * 2.0 * 255.0) as u8
                    } else {
                        255
                    };
                    blend_pixel(&mut rgba, x, y, alpha);
                }
            } else if fy <= body_top as f32 + 1.0 {
                // Vertical legs connecting arc to body
                let left_leg_center = shackle_center_x - shackle_outer_radius + stroke_width / 2.0;
                let right_leg_center = shackle_center_x + shackle_outer_radius - stroke_width / 2.0;

                let left_dist = (fx - left_leg_center).abs();
                let right_dist = (fx - right_leg_center).abs();

                if left_dist <= stroke_width / 2.0 + 0.5 {
                    let alpha = if left_dist > stroke_width / 2.0 {
                        ((stroke_width / 2.0 + 0.5 - left_dist) * 2.0 * 255.0) as u8
                    } else {
                        255
                    };
                    blend_pixel(&mut rgba, x, y, alpha);
                } else if right_dist <= stroke_width / 2.0 + 0.5 {
                    let alpha = if right_dist > stroke_width / 2.0 {
                        ((stroke_width / 2.0 + 0.5 - right_dist) * 2.0 * 255.0) as u8
                    } else {
                        255
                    };
                    blend_pixel(&mut rgba, x, y, alpha);
                }
            }
        }
    }

    // Draw keyhole in center of body (small circle + triangle pointing down)
    let keyhole_x = 10.5f32;
    let keyhole_y = 13.5f32;
    let keyhole_radius = 1.5f32;

    for y in 12..=17 {
        for x in 8..=13 {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;

            let dx = fx - keyhole_x;
            let dy = fy - keyhole_y;
            let dist = (dx * dx + dy * dy).sqrt();

            // Circle part of keyhole
            if dist <= keyhole_radius + 0.5 {
                let alpha = if dist > keyhole_radius {
                    ((keyhole_radius + 0.5 - dist) * 2.0 * 255.0) as u8
                } else {
                    255
                };
                // Subtract from existing (cut out the keyhole)
                let idx = (y * SIZE + x) * 4;
                let existing = rgba[idx + 3];
                rgba[idx + 3] = existing.saturating_sub(alpha);
            }

            // Triangle/slot part below circle
            if fy > keyhole_y && fy <= 17.0 {
                let slot_half_width = 1.0 - (fy - keyhole_y - 1.0) * 0.15;
                if slot_half_width > 0.0 && dx.abs() <= slot_half_width + 0.3 {
                    let alpha = if dx.abs() > slot_half_width {
                        ((slot_half_width + 0.3 - dx.abs()) * 3.0 * 255.0) as u8
                    } else {
                        255
                    };
                    let idx = (y * SIZE + x) * 4;
                    let existing = rgba[idx + 3];
                    rgba[idx + 3] = existing.saturating_sub(alpha);
                }
            }
        }
    }

    Icon::from_rgba(rgba, SIZE as u32, SIZE as u32)
        .map_err(|e| TrayError::IconCreation(e.to_string()))
}

