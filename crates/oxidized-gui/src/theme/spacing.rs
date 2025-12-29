//! Spacing scale constants (4px base).
//!
//! These constants provide a consistent spacing scale for use in inline styles.
//! For CSS-based styling, prefer using `var(--space-N)` custom properties.

/// No spacing
pub const SPACE_0: &str = "0";

/// 4px - Extra small spacing (icon gaps, tight padding)
pub const SPACE_1: &str = "4px";

/// 8px - Small spacing (within components, list item gaps)
pub const SPACE_2: &str = "8px";

/// 12px - Medium-small spacing (form field margins)
pub const SPACE_3: &str = "12px";

/// 16px - Medium spacing (standard component padding)
pub const SPACE_4: &str = "16px";

/// 20px - Medium-large spacing (dialog headers)
pub const SPACE_5: &str = "20px";

/// 24px - Large spacing (section padding, major gaps)
pub const SPACE_6: &str = "24px";

/// 32px - Extra large spacing (between major sections)
pub const SPACE_8: &str = "32px";

/// 40px - 2x large spacing (hero sections, major visual breaks)
pub const SPACE_10: &str = "40px";

// Border radius values

/// 4px - Small radius (buttons, small inputs)
pub const RADIUS_SM: &str = "4px";

/// 6px - Medium radius (standard inputs, buttons)
pub const RADIUS_MD: &str = "6px";

/// 8px - Large radius (cards, containers)
pub const RADIUS_LG: &str = "8px";

/// 12px - Extra large radius (dialogs, large cards)
pub const RADIUS_XL: &str = "12px";

/// Full radius (pills, circular elements)
pub const RADIUS_FULL: &str = "9999px";

// Common layout values

/// Standard sidebar width
pub const SIDEBAR_WIDTH: &str = "280px";

/// Standard icon size in buttons/list items
pub const ICON_SM: &str = "16px";

/// Medium icon size
pub const ICON_MD: &str = "20px";

/// Large icon size
pub const ICON_LG: &str = "24px";

/// Extra large icon size (feature icons)
pub const ICON_XL: &str = "32px";

/// Hero icon size (empty states, large visuals)
pub const ICON_HERO: &str = "64px";
