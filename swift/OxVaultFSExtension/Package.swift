// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OxVaultFSExtension",
    platforms: [
        .macOS("26.0")  // FSPathURLResource requires macOS 26.0
    ],
    products: [
        .library(
            name: "OxVaultFSExtension",
            targets: ["OxVaultFSExtension"]
        ),
    ],
    dependencies: [
        // OxVaultFFI now lives in the oxidized-fskit-ffi crate
        .package(name: "OxVaultFFI", path: "../../crates/oxidized-fskit-ffi/swift"),
    ],
    targets: [
        .target(
            name: "OxVaultFSExtension",
            dependencies: [
                .product(name: "OxVaultFFI", package: "OxVaultFFI")
            ],
            path: "Sources"
        ),
    ]
)
