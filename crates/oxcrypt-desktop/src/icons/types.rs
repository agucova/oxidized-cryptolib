//! Icon types shared across platforms
//!
//! Maps icon names to SF Symbols (macOS) and Heroicons (fallback).

/// Icon names with mappings to platform-specific implementations
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IconName {
    /// Locked vault - lock.fill / lock-closed
    Lock,
    /// Unlocked vault - lock.open.fill / lock-open
    LockOpen,
    /// Folder (closed) - folder.fill / folder
    Folder,
    /// Folder (open) - folder.fill / folder-open
    FolderOpen,
    /// Settings/gear - gear / cog-6-tooth
    Gear,
    /// Statistics/chart - chart.bar.fill / chart-bar
    ChartBar,
    /// Warning/alert - exclamationmark.triangle.fill / exclamation-triangle
    Warning,
    /// Error/X - xmark.circle.fill / x-circle
    XCircle,
    /// Info - info.circle.fill / information-circle
    InfoCircle,
    /// Plus/add - plus / plus
    Plus,
    /// Chevron right - chevron.right / chevron-right
    ChevronRight,
    /// Trash/delete - trash.fill / trash
    Trash,
    /// Key/password - key.fill / key
    Key,
    /// Check/success - checkmark.circle.fill / check-circle
    CheckCircle,
    /// Eye (show password) - eye.fill / eye
    Eye,
    /// Eye slash (hide password) - eye.slash.fill / eye-slash
    EyeSlash,
    /// Arrow path (sync/refresh) - arrow.triangle.2.circlepath / arrow-path
    ArrowPath,
    /// Document - doc.fill / document
    Document,
    /// Eject - eject.fill / arrow-up-on-square
    Eject,
    /// Ellipsis vertical (menu) - ellipsis.vertical / ellipsis-vertical
    EllipsisVertical,
}

impl IconName {
    /// SF Symbol name (macOS)
    pub fn sf_symbol(self) -> &'static str {
        match self {
            Self::Lock => "lock.fill",
            Self::LockOpen => "lock.open.fill",
            Self::Folder | Self::FolderOpen => "folder.fill", // SF Symbols doesn't have open variant
            Self::Gear => "gear",
            Self::ChartBar => "chart.bar.fill",
            Self::Warning => "exclamationmark.triangle.fill",
            Self::XCircle => "xmark.circle.fill",
            Self::InfoCircle => "info.circle.fill",
            Self::Plus => "plus",
            Self::ChevronRight => "chevron.right",
            Self::Trash => "trash.fill",
            Self::Key => "key.fill",
            Self::CheckCircle => "checkmark.circle.fill",
            Self::Eye => "eye.fill",
            Self::EyeSlash => "eye.slash.fill",
            Self::ArrowPath => "arrow.triangle.2.circlepath",
            Self::Document => "doc.fill",
            Self::Eject => "eject.fill",
            Self::EllipsisVertical => "ellipsis.circle", // circled ellipsis
        }
    }

    /// Heroicon name (fallback)
    #[allow(dead_code)]
    pub fn heroicon(self) -> &'static str {
        match self {
            Self::Lock => "lock-closed",
            Self::LockOpen => "lock-open",
            Self::Folder => "folder",
            Self::FolderOpen => "folder-open",
            Self::Gear => "cog-6-tooth",
            Self::ChartBar => "chart-bar",
            Self::Warning => "exclamation-triangle",
            Self::XCircle => "x-circle",
            Self::InfoCircle => "information-circle",
            Self::Plus => "plus",
            Self::ChevronRight => "chevron-right",
            Self::Trash => "trash",
            Self::Key => "key",
            Self::CheckCircle => "check-circle",
            Self::Eye => "eye",
            Self::EyeSlash => "eye-slash",
            Self::ArrowPath => "arrow-path",
            Self::Document => "document",
            Self::Eject => "arrow-up-on-square",
            Self::EllipsisVertical => "ellipsis-vertical",
        }
    }
}

/// Icon size in points
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IconSize(pub u32);

impl Default for IconSize {
    fn default() -> Self {
        Self(16)
    }
}

impl From<u32> for IconSize {
    fn from(size: u32) -> Self {
        Self(size)
    }
}

/// Icon weight (thickness)
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum IconWeight {
    Ultralight,
    Thin,
    Light,
    #[default]
    Regular,
    Medium,
    Semibold,
    Bold,
    Heavy,
    Black,
}

impl IconWeight {
    /// Convert to SF Symbol weight value (CGFloat)
    /// Values from NSFontWeight constants
    #[allow(dead_code)]
    pub fn sf_weight(self) -> f64 {
        match self {
            Self::Ultralight => -0.8,
            Self::Thin => -0.6,
            Self::Light => -0.4,
            Self::Regular => 0.0,
            Self::Medium => 0.23,
            Self::Semibold => 0.3,
            Self::Bold => 0.4,
            Self::Heavy => 0.56,
            Self::Black => 0.62,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ultralight => "ultralight",
            Self::Thin => "thin",
            Self::Light => "light",
            Self::Regular => "regular",
            Self::Medium => "medium",
            Self::Semibold => "semibold",
            Self::Bold => "bold",
            Self::Heavy => "heavy",
            Self::Black => "black",
        }
    }
}

/// Icon color - supports common semantic colors
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum IconColor {
    /// Adapts to current context (white in dark mode, black in light)
    #[default]
    Primary,
    /// Muted/secondary color
    Secondary,
    /// Success/positive (green)
    Success,
    /// Warning (yellow/orange)
    Warning,
    /// Error/danger (red)
    Danger,
    /// Accent/brand color (blue)
    Accent,
    /// Adaptive icon color for light UI on macOS (black, invert in dark mode)
    Adaptive,
}

impl IconColor {
    /// CSS color value for Heroicons
    #[allow(dead_code)]
    pub fn css_color(self) -> &'static str {
        match self {
            Self::Primary => "currentColor",
            Self::Secondary => "rgb(107, 114, 128)", // gray-500
            Self::Success => "rgb(34, 197, 94)",     // green-500
            Self::Warning => "rgb(234, 179, 8)",     // yellow-500
            Self::Danger => "rgb(239, 68, 68)",      // red-500
            Self::Accent => "rgb(59, 130, 246)",     // blue-500
            Self::Adaptive => "currentColor",
        }
    }

    /// Hex color for SF Symbol tinting
    pub fn hex_color(self) -> &'static str {
        match self {
            Self::Primary => "ffffff",   // White for dark mode (our default)
            Self::Secondary => "6b7280", // gray-500
            Self::Success => "22c55e",   // green-500
            Self::Warning => "eab308",   // yellow-500
            Self::Danger => "ef4444",    // red-500
            Self::Accent => "3b82f6",    // blue-500
            Self::Adaptive => "000000",  // Black for light mode (invert in dark)
        }
    }
}
