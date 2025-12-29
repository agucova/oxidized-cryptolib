// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OxVaultFFI",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "OxVaultFFI",
            targets: ["OxVaultFFI"]
        ),
    ],
    targets: [
        // C headers from swift-bridge
        .target(
            name: "COxVaultFFI",
            path: "include",
            publicHeadersPath: "."
        ),
        // Swift wrapper
        .target(
            name: "OxVaultFFI",
            dependencies: ["COxVaultFFI"],
            path: "Sources/OxVaultFFI"
            // Linker settings are provided by the consuming Xcode project
        ),
        // Integration tests
        .testTarget(
            name: "OxVaultFFITests",
            dependencies: ["OxVaultFFI"],
            path: "Tests/OxVaultFFITests",
            linkerSettings: [
                // Link against the Rust static library for tests
                .unsafeFlags([
                    "-L", "../../../../target/release",
                    "-loxidized_fskit_ffi"
                ])
            ]
        ),
    ]
)
