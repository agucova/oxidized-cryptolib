// Build script to embed pre-built extension app and configure swift_bridge

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

fn main() {
    // Configure swift_bridge to generate FFI bindings
    configure_swift_bridge();

    let extension_bundle = PathBuf::from("extension/build/OxCryptFileProvider.app");

    if extension_bundle.exists() {
        println!("cargo:rerun-if-changed=extension/build/OxCryptFileProvider.app");
        println!(
            "cargo:rustc-env=EXTENSION_BUNDLE_PATH={}",
            extension_bundle.display()
        );

        // Compute hash for integrity verification
        match compute_bundle_hash(&extension_bundle) {
            Ok(hash) => {
                println!("cargo:rustc-env=EXTENSION_SHA256={}", hash);
            }
            Err(e) => {
                println!("cargo:warning=Failed to compute extension hash: {}", e);
                println!("cargo:rustc-env=EXTENSION_SHA256=unknown");
            }
        }

        // Warn about binary size impact
        match bundle_size(&extension_bundle) {
            Ok(size) => {
                let size_mb = size / 1_000_000;
                println!(
                    "cargo:warning=Embedding FileProvider extension ({} MB)",
                    size_mb
                );
            }
            Err(e) => {
                println!(
                    "cargo:warning=Could not determine extension bundle size: {}",
                    e
                );
            }
        }
    } else {
        // Create empty placeholder directory to prevent include_dir!() from panicking
        // The extension_manager.rs code checks EXTENSION_SHA256 to determine if bundle is usable
        if let Err(e) = fs::create_dir_all(&extension_bundle) {
            println!("cargo:warning=Failed to create placeholder directory: {}", e);
        }

        println!("cargo:warning==============================================");
        println!("cargo:warning=FileProvider extension not built");
        println!("cargo:warning=");
        println!("cargo:warning=To build the extension, run:");
        println!("cargo:warning=  fileprovider-build         (in devenv)");
        println!("cargo:warning=  ./extension/build.sh       (manually)");
        println!("cargo:warning=");
        println!("cargo:warning=Then rebuild: cargo build -p oxcrypt-fileprovider");
        println!("cargo:warning==============================================");
        println!("cargo:rustc-env=EXTENSION_SHA256=not_built");
        println!("cargo:rustc-env=EXTENSION_BUNDLE_PATH=");
    }
}

fn compute_bundle_hash(bundle_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();

    // Hash all files in bundle (recursive)
    hash_directory(&mut hasher, bundle_path)?;

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

fn hash_directory(hasher: &mut Sha256, dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            hash_directory(hasher, &path)?;
        } else {
            let mut file = fs::File::open(&path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            hasher.update(&buffer);
        }
    }

    Ok(())
}

fn bundle_size(bundle_path: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    let mut total = 0;

    for entry in fs::read_dir(bundle_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            total += bundle_size(&path)?;
        } else {
            total += fs::metadata(&path)?.len();
        }
    }

    Ok(total)
}

/// Configure swift_bridge to generate FFI bindings.
///
/// This parses Rust code for swift_bridge macros and generates Swift headers
/// that can be imported by the Xcode project.
fn configure_swift_bridge() {
    // Parse bridges from lib.rs
    let bridge = swift_bridge_build::parse_bridges(vec!["src/lib.rs"]);

    // Generate Swift code in extension/Shared/generated/
    let output_dir = PathBuf::from("extension/Shared/generated");

    // Create output directory if it doesn't exist
    if !output_dir.exists() {
        if let Err(e) = fs::create_dir_all(&output_dir) {
            println!("cargo:warning=Failed to create swift_bridge output directory: {}", e);
            return;
        }
    }

    // Write all bridges to the output directory
    // write_all_concatenated creates a header in the directory, not a single file
    bridge.write_all_concatenated(&output_dir, "generated");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/xpc.rs");
    println!("cargo:rerun-if-changed=src/xpc_client.swift");
}
