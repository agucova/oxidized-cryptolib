//! Platform-specific utilities.

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::*;

/// Check if FSKit is available on the current platform.
#[cfg(not(target_os = "macos"))]
pub fn fskit_available() -> bool {
    false
}

/// Get the macOS version (returns None on non-macOS).
#[cfg(not(target_os = "macos"))]
pub fn macos_version() -> Option<(u32, u32, u32)> {
    None
}
