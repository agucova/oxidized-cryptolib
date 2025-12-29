//! Icon system with native SF Symbols on macOS and Heroicons fallback
//!
//! Provides a unified `Icon` component that automatically uses the best
//! icon system for the current platform:
//! - macOS: Native SF Symbols via custom protocol handler
//! - Other platforms: Heroicons SVGs embedded inline

pub mod heroicons;
#[cfg(target_os = "macos")]
pub mod sfsymbol;
pub mod types;

#[cfg(target_os = "macos")]
pub use sfsymbol::handle_sfsymbol_request;

pub use types::{IconColor, IconName, IconSize, IconWeight};

use dioxus::prelude::*;

/// Unified Icon component - uses SF Symbols on macOS, Heroicons elsewhere
///
/// # Example
///
/// ```ignore
/// Icon { name: IconName::Lock, size: 24.into() }
/// Icon { name: IconName::Gear, size: 16.into(), color: IconColor::Secondary }
/// ```
#[component]
pub fn Icon(
    /// The icon to display
    name: IconName,
    /// Size in points (default: 16)
    #[props(default)]
    size: IconSize,
    /// Weight/thickness (default: Regular) - macOS only
    #[props(default)]
    weight: IconWeight,
    /// Color (default: Primary/white in dark mode)
    #[props(default)]
    color: IconColor,
    /// Additional CSS classes
    #[props(default)]
    class: String,
) -> Element {
    let size_px = size.0;

    #[cfg(target_os = "macos")]
    {
        // Use SF Symbols via custom protocol
        let src = format!(
            "sfsymbol://{}?size={}&weight={}&color={}",
            name.sf_symbol(),
            size_px,
            weight.as_str(),
            color.hex_color(),
        );
        rsx! {
            img {
                src: "{src}",
                width: "{size_px}",
                height: "{size_px}",
                class: "icon {class}",
                alt: "",
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Use Heroicons SVG inline
        let svg = heroicons::render_heroicon_svg(name, size_px, color.css_color());
        rsx! {
            span {
                class: "icon icon-svg {class}",
                dangerous_inner_html: "{svg}",
            }
        }
    }
}
