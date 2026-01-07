//! macOS SF Symbol rendering via AppKit
//!
//! Renders SF Symbols to PNG via custom protocol handler with color tinting support.

use std::borrow::Cow;
use std::collections::HashMap;

use dioxus::desktop::wry::WebViewId;
use image::RgbaImage;
use objc2_app_kit::{NSImage, NSImageSymbolConfiguration, NSImageSymbolScale};
use objc2_foundation::NSString;

/// Handle requests for sfsymbol:// URLs
///
/// URL format: `sfsymbol://symbol.name?size=24&color=ffffff`
/// Example: `sfsymbol://lock.fill?size=24&color=ff0000`
#[allow(clippy::needless_pass_by_value)] // Protocol handler signature requires ownership
pub fn handle_sfsymbol_request(
    _webview_id: WebViewId<'_>,
    request: dioxus::desktop::wry::http::Request<Vec<u8>>,
) -> dioxus::desktop::wry::http::Response<Cow<'static, [u8]>> {
    let uri = request.uri();

    // Parse symbol name from host
    let symbol_name = uri.host().unwrap_or("questionmark");

    // Parse query parameters
    let params = parse_query_params(uri.query().unwrap_or(""));
    let size: u32 = params
        .get("size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    let weight: f64 = params
        .get("weight")
        .and_then(|s| parse_weight(s))
        .unwrap_or(0.0);
    let color = params.get("color").map(std::string::String::as_str);

    tracing::debug!(
        "SF Symbol request: {} @ {}pt, weight={}, color={:?}",
        symbol_name,
        size,
        weight,
        color
    );

    // Render the symbol
    match render_sf_symbol(symbol_name, size, weight, color) {
        Some(png_data) => {
            tracing::debug!("SF Symbol rendered: {} bytes", png_data.len());
            dioxus::desktop::wry::http::Response::builder()
                .status(200)
                .header("Content-Type", "image/png")
                .header("Cache-Control", "max-age=86400")
                .body(Cow::Owned(png_data))
                .unwrap()
        }
        None => {
            tracing::warn!("Failed to render SF Symbol: {}", symbol_name);
            // Return empty response on failure
            static EMPTY: &[u8] = &[];
            dioxus::desktop::wry::http::Response::builder()
                .status(404)
                .body(Cow::Borrowed(EMPTY))
                .unwrap()
        }
    }
}

/// Parse URL query string into a HashMap
fn parse_query_params(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Parse weight string to NSFontWeight value
fn parse_weight(s: &str) -> Option<f64> {
    Some(match s.to_lowercase().as_str() {
        "ultralight" => -0.8,
        "thin" => -0.6,
        "light" => -0.4,
        "regular" => 0.0,
        "medium" => 0.23,
        "semibold" => 0.3,
        "bold" => 0.4,
        "heavy" => 0.56,
        "black" => 0.62,
        _ => return s.parse().ok(),
    })
}

/// Parse hex color string (e.g., "ff0000" or "ffffff")
fn parse_hex_color(hex: &str) -> Option<(u8, u8, u8)> {
    if hex.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some((r, g, b))
}

/// Apply a tint color to an RGBA image
///
/// SF Symbols render as grayscale with alpha. We replace the RGB values
/// with the tint color while preserving the alpha channel.
fn apply_tint(img: &mut RgbaImage, r: u8, g: u8, b: u8) {
    for pixel in img.pixels_mut() {
        // Preserve alpha, replace RGB with tint color
        pixel[0] = r;
        pixel[1] = g;
        pixel[2] = b;
        // pixel[3] (alpha) stays unchanged
    }
}

/// Render an SF Symbol to PNG data
///
/// Uses NSImage's TIFF representation and converts to PNG via the `image` crate.
/// Optionally applies a tint color.
fn render_sf_symbol(name: &str, size: u32, weight: f64, color: Option<&str>) -> Option<Vec<u8>> {
    unsafe {
        // Load SF Symbol by name
        let name_str = NSString::from_str(name);
        let image = NSImage::imageWithSystemSymbolName_accessibilityDescription(&name_str, None)?;

        // Create symbol configuration with size and weight
        // Render at 3x for crisp retina display
        let config = NSImageSymbolConfiguration::configurationWithPointSize_weight_scale(
            f64::from(size) * 3.0,
            weight,
            NSImageSymbolScale::Large,
        );

        // Apply configuration
        let configured_image = image.imageWithSymbolConfiguration(&config)?;

        // Get TIFF representation (simpler API than creating bitmap context)
        let tiff_data = configured_image.TIFFRepresentation()?;

        // Get bytes from NSData using as_bytes_unchecked
        // SAFETY: We own the tiff_data and don't mutate it while reading
        let tiff_bytes: Vec<u8> = tiff_data.as_bytes_unchecked().to_vec();

        // Convert TIFF to RGBA image
        let mut img = image::load_from_memory_with_format(&tiff_bytes, image::ImageFormat::Tiff)
            .ok()?
            .into_rgba8();

        // Apply tint color if specified
        if let Some(hex) = color
            && let Some((r, g, b)) = parse_hex_color(hex) {
                apply_tint(&mut img, r, g, b);
            }

        // Encode as PNG
        let mut png_bytes = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_bytes),
            image::ImageFormat::Png,
        )
        .ok()?;

        Some(png_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_lock_fill() {
        let result = render_sf_symbol("lock.fill", 24, 0.0, None);
        assert!(result.is_some(), "Should render lock.fill symbol");
        let png_data = result.unwrap();
        assert!(!png_data.is_empty(), "PNG data should not be empty");
        // PNG magic bytes
        assert_eq!(
            &png_data[0..4],
            &[0x89, 0x50, 0x4E, 0x47],
            "Should be valid PNG"
        );
    }

    #[test]
    fn test_render_with_color() {
        let result = render_sf_symbol("gear", 24, 0.0, Some("ff0000"));
        assert!(result.is_some(), "Should render gear symbol with color");
        let png_data = result.unwrap();
        assert!(!png_data.is_empty(), "PNG data should not be empty");
    }

    #[test]
    fn test_render_nonexistent_symbol() {
        let result = render_sf_symbol("this.symbol.does.not.exist.12345", 24, 0.0, None);
        assert!(result.is_none(), "Should return None for nonexistent symbol");
    }

    #[test]
    fn test_parse_hex_color() {
        assert_eq!(parse_hex_color("ff0000"), Some((255, 0, 0)));
        assert_eq!(parse_hex_color("00ff00"), Some((0, 255, 0)));
        assert_eq!(parse_hex_color("ffffff"), Some((255, 255, 255)));
        assert_eq!(parse_hex_color("invalid"), None);
        assert_eq!(parse_hex_color("fff"), None);
    }
}
