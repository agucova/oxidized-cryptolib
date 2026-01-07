//! Build script for swift-bridge code generation and Objective-C protocol compilation.
//!
//! Parses the bridge module definitions in src/lib.rs and generates:
//! - Swift bindings (.swift files)
//! - C header (.h file)
//!
//! Also compiles the OxVaultServiceProtocol.m file so the XPC protocol
//! is registered in the Objective-C runtime.

use std::path::PathBuf;

fn main() {
    // Output to generated/ directory as per swift-bridge docs
    let out_dir = PathBuf::from("./generated");

    let bridges = vec!["src/lib.rs"];
    for path in &bridges {
        println!("cargo:rerun-if-changed={path}");
    }

    swift_bridge_build::parse_bridges(bridges)
        .write_all_concatenated(out_dir, env!("CARGO_PKG_NAME"));

    // Compile the Objective-C protocol definition.
    // The protocol is referenced via extern "C" fn OxVaultServiceProtocol_get() in connection.rs,
    // which forces the linker to include the symbols.
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=objc/OxVaultServiceProtocol.h");
        println!("cargo:rerun-if-changed=objc/OxVaultServiceProtocol.m");

        cc::Build::new()
            .file("objc/OxVaultServiceProtocol.m")
            .include("objc")
            .flag("-fobjc-arc") // Enable ARC
            .flag("-Wno-nullability-completeness") // Suppress nullability warnings
            .compile("oxvaultprotocol");

        // Link Foundation framework (required for NSObject, Protocol, etc.)
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
