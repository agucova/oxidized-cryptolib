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
            .with_menu_on_left_click(true) // Show menu on click, not open window
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
/// Creates a 22x22 icon suitable for macOS menu bar.
/// Uses SDF (signed distance field) rendering for smooth anti-aliased edges.
fn create_default_icon() -> Result<Icon, TrayError> {
    // 22x22 is the standard macOS menu bar icon size
    // We render at 2x (44x44) for better quality, then the system scales
    const SIZE: usize = 44;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];

    // SDF helper: returns smooth alpha based on signed distance
    // Negative distance = inside shape, positive = outside
    let sdf_alpha = |dist: f32| -> u8 {
        // Smooth transition over ~1.5 pixels for anti-aliasing
        let edge = 0.0;
        let smoothness = 1.2;
        let t = ((edge - dist) / smoothness + 0.5).clamp(0.0, 1.0);
        (t * 255.0) as u8
    };

    // SDF for rounded rectangle
    let sdf_rounded_rect =
        |px: f32, py: f32, cx: f32, cy: f32, half_w: f32, half_h: f32, radius: f32| -> f32 {
            let dx = (px - cx).abs() - half_w + radius;
            let dy = (py - cy).abs() - half_h + radius;
            let outside_dist = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
            let inside_dist = dx.max(dy).min(0.0);
            outside_dist + inside_dist - radius
        };

    // SDF for circle
    let sdf_circle = |px: f32, py: f32, cx: f32, cy: f32, radius: f32| -> f32 {
        let dx = px - cx;
        let dy = py - cy;
        (dx * dx + dy * dy).sqrt() - radius
    };

    // SDF for the shackle (rounded U-shape, hollow)
    let sdf_shackle =
        |px: f32, py: f32, cx: f32, cy: f32, outer_r: f32, thickness: f32| -> f32 {
            let dx = px - cx;
            let dy = py - cy;
            let dist_from_center = (dx * dx + dy * dy).sqrt();

            // Annulus (ring) distance
            let ring_dist = (dist_from_center - (outer_r - thickness / 2.0)).abs() - thickness / 2.0;

            // Only keep top half (y <= cy) and the legs
            if py <= cy {
                ring_dist
            } else {
                // Vertical legs
                let leg_left_x = cx - outer_r + thickness / 2.0;
                let leg_right_x = cx + outer_r - thickness / 2.0;

                let left_dist = ((px - leg_left_x).abs() - thickness / 2.0).max(0.0);
                let right_dist = ((px - leg_right_x).abs() - thickness / 2.0).max(0.0);

                left_dist.min(right_dist)
            }
        };

    // Icon geometry (at 2x scale)
    let center_x = SIZE as f32 / 2.0;

    // Lock body: rounded rectangle
    let body_cx = center_x;
    let body_cy = 28.0;
    let body_half_w = 11.0;
    let body_half_h = 9.0;
    let body_radius = 3.0;

    // Shackle: semi-circle with legs
    let shackle_cx = center_x;
    let shackle_cy = 18.0;
    let shackle_outer_r = 9.0;
    let shackle_thickness = 4.0;

    // Keyhole
    let keyhole_cx = center_x;
    let keyhole_cy = 26.0;
    let keyhole_radius = 3.0;
    let keyhole_slot_width = 2.5;
    let keyhole_slot_height = 6.0;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;

            // Calculate SDFs for each shape
            let body_dist = sdf_rounded_rect(px, py, body_cx, body_cy, body_half_w, body_half_h, body_radius);
            let shackle_dist = sdf_shackle(px, py, shackle_cx, shackle_cy, shackle_outer_r, shackle_thickness);

            // Combine body and shackle (union = min)
            let lock_dist = body_dist.min(shackle_dist);

            // Keyhole cutout (circle + rectangle slot)
            let keyhole_circle_dist = sdf_circle(px, py, keyhole_cx, keyhole_cy, keyhole_radius);
            let keyhole_slot_dist = sdf_rounded_rect(
                px,
                py,
                keyhole_cx,
                keyhole_cy + keyhole_slot_height / 2.0,
                keyhole_slot_width / 2.0,
                keyhole_slot_height / 2.0,
                1.0,
            );
            let keyhole_dist = keyhole_circle_dist.min(keyhole_slot_dist);

            // Subtract keyhole from lock (lock AND NOT keyhole)
            // For SDF subtraction: max(a, -b)
            let final_dist = lock_dist.max(-keyhole_dist);

            let alpha = sdf_alpha(-final_dist);

            if alpha > 0 {
                let idx = (y * SIZE + x) * 4;
                rgba[idx] = 255;     // R (white)
                rgba[idx + 1] = 255; // G
                rgba[idx + 2] = 255; // B
                rgba[idx + 3] = alpha;
            }
        }
    }

    Icon::from_rgba(rgba, SIZE as u32, SIZE as u32)
        .map_err(|e| TrayError::IconCreation(e.to_string()))
}

