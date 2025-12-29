//! Platform detection and platform-specific utilities
//!
//! Provides platform detection for macOS, Linux, and Windows to enable
//! platform-specific styling and behavior.

/// Detected platform
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
    Unknown,
}

impl Platform {
    /// Detect the current platform at compile time
    pub const fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Platform::MacOS
        }
        #[cfg(target_os = "linux")]
        {
            Platform::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Platform::Windows
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Platform::Unknown
        }
    }

    /// Get CSS class for platform-specific styling
    pub const fn css_class(&self) -> &'static str {
        match self {
            Platform::MacOS => "platform-macos",
            Platform::Linux => "platform-linux",
            Platform::Windows => "platform-windows",
            Platform::Unknown => "platform-unknown",
        }
    }

    /// Get the keyboard modifier name for this platform
    ///
    /// Returns "Cmd" on macOS, "Ctrl" on Linux/Windows
    pub const fn modifier_name(&self) -> &'static str {
        match self {
            Platform::MacOS => "Cmd",
            _ => "Ctrl",
        }
    }

    /// Get the keyboard modifier symbol for this platform
    ///
    /// Returns "⌘" on macOS, "Ctrl" on Linux/Windows
    pub const fn modifier_symbol(&self) -> &'static str {
        match self {
            Platform::MacOS => "⌘",
            _ => "Ctrl",
        }
    }

    /// Check if this is macOS
    pub const fn is_macos(&self) -> bool {
        matches!(self, Platform::MacOS)
    }

    /// Check if this is Linux
    pub const fn is_linux(&self) -> bool {
        matches!(self, Platform::Linux)
    }

    /// Check if this is Windows
    pub const fn is_windows(&self) -> bool {
        matches!(self, Platform::Windows)
    }

    /// Get the settings/preferences menu item label
    ///
    /// Returns "Settings" on macOS, "Preferences" on Linux, "Options" on Windows
    pub const fn settings_label(&self) -> &'static str {
        match self {
            Platform::MacOS => "Settings",
            Platform::Linux => "Preferences",
            Platform::Windows => "Options",
            Platform::Unknown => "Settings",
        }
    }

    /// Get the quit/exit menu item label
    ///
    /// Returns "Quit" on macOS/Linux, "Exit" on Windows
    pub const fn quit_label(&self) -> &'static str {
        match self {
            Platform::Windows => "Exit",
            _ => "Quit",
        }
    }

    /// Get the "Reveal in Finder/Explorer" label
    pub const fn reveal_label(&self) -> &'static str {
        match self {
            Platform::MacOS => "Reveal in Finder",
            Platform::Windows => "Show in Explorer",
            _ => "Open Location",
        }
    }
}

/// Get the current platform (convenience function)
pub const fn current_platform() -> Platform {
    Platform::current()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = Platform::current();

        #[cfg(target_os = "macos")]
        assert_eq!(platform, Platform::MacOS);

        #[cfg(target_os = "linux")]
        assert_eq!(platform, Platform::Linux);

        #[cfg(target_os = "windows")]
        assert_eq!(platform, Platform::Windows);
    }

    #[test]
    fn test_css_class() {
        assert_eq!(Platform::MacOS.css_class(), "platform-macos");
        assert_eq!(Platform::Linux.css_class(), "platform-linux");
        assert_eq!(Platform::Windows.css_class(), "platform-windows");
    }

    #[test]
    fn test_modifier_symbol() {
        assert_eq!(Platform::MacOS.modifier_symbol(), "⌘");
        assert_eq!(Platform::Linux.modifier_symbol(), "Ctrl");
        assert_eq!(Platform::Windows.modifier_symbol(), "Ctrl");
    }
}
