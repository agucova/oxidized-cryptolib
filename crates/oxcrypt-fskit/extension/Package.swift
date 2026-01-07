// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OxVaultFSExtension",
    platforms: [
        .macOS("26.0")  // FSPathURLResource requires macOS 26.0
    ],
    products: [
        .executable(
            name: "OxVaultFSExtension",
            targets: ["OxVaultFSExtension"]
        ),
    ],
    dependencies: [
        // OxVaultFFI FFI bindings from the same crate
        .package(name: "OxVaultFFI", path: "../swift"),
    ],
    targets: [
        .executableTarget(
            name: "OxVaultFSExtension",
            dependencies: [
                .product(name: "OxVaultFFI", package: "OxVaultFFI")
            ],
            path: "Sources",
            linkerSettings: [
                // Link against the Rust static library
                .unsafeFlags([
                    "-L", "../../../target/release",
                    "-loxcrypt_fskit"
                ])
            ]
        ),
        .testTarget(
            name: "OxVaultFSExtensionTests",
            dependencies: [
                "OxVaultFSExtension",
                .product(name: "OxVaultFFI", package: "OxVaultFFI")
            ],
            path: "Tests"
        ),
    ]
)
