//! Theme module providing design tokens for consistent styling.
//!
//! This module provides Rust constants that complement the CSS custom properties
//! defined in `assets/main.css`. Use CSS variables (via `var(--name)`) for colors
//! that need to support theming (light/dark mode), and use these Rust constants
//! for static values like spacing and typography.

mod spacing;
mod typography;

pub use spacing::*;
pub use typography::*;

/// Common style patterns as format strings.
///
/// These helpers generate frequently-used style combinations.
pub mod styles {
    use super::*;

    /// Generate flexbox styles for centering content
    pub fn flex_center() -> &'static str {
        "display: flex; align-items: center; justify-content: center;"
    }

    /// Generate flexbox column layout
    pub fn flex_column() -> &'static str {
        "display: flex; flex-direction: column;"
    }

    /// Generate flexbox row layout with gap
    pub fn flex_row_gap(gap: &str) -> String {
        format!("display: flex; align-items: center; gap: {};", gap)
    }

    /// Generate card container style using CSS variables
    pub fn card() -> &'static str {
        "background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-lg); padding: var(--space-4);"
    }

    /// Generate raised card style with shadow
    pub fn card_raised() -> &'static str {
        "background: var(--color-surface-raised); border-radius: var(--radius-lg); padding: var(--space-4); box-shadow: var(--shadow-sm);"
    }

    /// Generate interactive card style
    pub fn card_interactive() -> &'static str {
        "background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-lg); padding: var(--space-4); cursor: pointer; transition: all 150ms ease;"
    }

    /// Generate dialog backdrop style
    pub fn dialog_backdrop() -> &'static str {
        "position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;"
    }

    /// Generate dialog container style
    pub fn dialog_container() -> &'static str {
        "background: var(--color-surface); border-radius: var(--radius-xl); box-shadow: var(--shadow-xl); max-width: 480px; width: 90%;"
    }

    /// Generate section header label style
    pub fn section_label() -> &'static str {
        "font-size: var(--font-size-xs); font-weight: var(--font-weight-semibold); color: var(--color-text-tertiary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: var(--space-3);"
    }
}
