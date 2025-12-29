//! Build script for swift-bridge code generation.
//!
//! Parses the bridge module definitions in src/lib.rs and generates:
//! - Swift bindings (.swift files)
//! - C header (.h file)

use std::path::PathBuf;

fn main() {
    // Output to generated/ directory as per swift-bridge docs
    let out_dir = PathBuf::from("./generated");

    let bridges = vec!["src/lib.rs"];
    for path in &bridges {
        println!("cargo:rerun-if-changed={}", path);
    }

    swift_bridge_build::parse_bridges(bridges)
        .write_all_concatenated(out_dir, env!("CARGO_PKG_NAME"));
}
