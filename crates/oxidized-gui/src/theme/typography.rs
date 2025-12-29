//! Typography constants for consistent text styling.
//!
//! These constants provide a type scale for use in inline styles.
//! For CSS-based styling, prefer using `var(--font-size-N)` custom properties.

// Font sizes

/// 11px - Extra small text (badges, timestamps)
pub const TEXT_XS: &str = "11px";

/// 12px - Small text (captions, labels, helper text)
pub const TEXT_SM: &str = "12px";

/// 14px - Base text size (body text, buttons)
pub const TEXT_BASE: &str = "14px";

/// 16px - Medium text (emphasized body, input text)
pub const TEXT_MD: &str = "16px";

/// 18px - Large text (sidebar titles, section headers)
pub const TEXT_LG: &str = "18px";

/// 20px - Extra large text (dialog titles)
pub const TEXT_XL: &str = "20px";

/// 24px - 2x large text (detail panel headers)
pub const TEXT_2XL: &str = "24px";

// Font weights

/// 400 - Normal weight (body text)
pub const WEIGHT_NORMAL: &str = "400";

/// 500 - Medium weight (buttons, links, emphasized text)
pub const WEIGHT_MEDIUM: &str = "500";

/// 600 - Semibold weight (headings, labels)
pub const WEIGHT_SEMIBOLD: &str = "600";

/// 700 - Bold weight (strong emphasis)
pub const WEIGHT_BOLD: &str = "700";

// Line heights

/// 1.25 - Tight line height (headings, single lines)
pub const LINE_TIGHT: &str = "1.25";

/// 1.5 - Normal line height (body text)
pub const LINE_NORMAL: &str = "1.5";

/// 1.6 - Relaxed line height (readable paragraphs)
pub const LINE_RELAXED: &str = "1.6";
