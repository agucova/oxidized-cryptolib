//! macOS-specific platform utilities.

use std::process::Command;

/// Get the macOS version as (major, minor, patch).
pub fn macos_version() -> Option<(u32, u32, u32)> {
    let output = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    parse_version(&version_str)
}

/// Parse a version string like "15.4.0" or "15.4" into (major, minor, patch).
fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.is_empty() {
        return None;
    }

    let major: u32 = parts.first()?.parse().ok()?;
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    Some((major, minor, patch))
}

/// Check if FSKit is available (requires macOS 15.4+).
pub fn fskit_available() -> bool {
    match macos_version() {
        Some((major, minor, _)) => {
            // FSKit requires macOS 15.4 or later
            major > 15 || (major == 15 && minor >= 4)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("15.4.0"), Some((15, 4, 0)));
        assert_eq!(parse_version("15.4"), Some((15, 4, 0)));
        assert_eq!(parse_version("14.6.1"), Some((14, 6, 1)));
        assert_eq!(parse_version("15"), Some((15, 0, 0)));
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn test_fskit_available_logic() {
        // Test version comparison logic directly
        fn check(major: u32, minor: u32) -> bool {
            major > 15 || (major == 15 && minor >= 4)
        }

        assert!(!check(14, 0));
        assert!(!check(15, 0));
        assert!(!check(15, 3));
        assert!(check(15, 4));
        assert!(check(15, 5));
        assert!(check(16, 0));
    }
}
