// swift-tools-version:5.9
//
// Swift harness for the `keys-iroh-sync` uniffi facade.
//
// Sibling to ../swift-harness/ (which wraps keys-ffi). Two packages
// because the two crates use deliberately different uniffi versions
// — see ../crates/keys-iroh-sync/Cargo.toml for the rationale.
//
// `KeysIrohSyncFFI.xcframework` and `Sources/KeysIrohSyncFFI/` are
// produced by `../bindgen/build-swift-iroh-sync.sh` and are
// gitignored — run that script before `swift build` or any Xcode
// build that consumes this package.

import PackageDescription

let package = Package(
    name: "KeysIrohSyncFFI",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "KeysIrohSyncFFI", targets: ["KeysIrohSyncFFI"]),
    ],
    targets: [
        .binaryTarget(
            name: "KeysIrohSyncFFIBinary",
            path: "KeysIrohSyncFFI.xcframework"
        ),
        .target(
            name: "KeysIrohSyncFFI",
            dependencies: ["KeysIrohSyncFFIBinary"],
            path: "Sources/KeysIrohSyncFFI",
            // iroh's transitive `system_configuration` crate links the
            // SystemConfiguration framework for home-network detection.
            // The Rust crate emits `#[link(name = "SystemConfiguration",
            // kind = "framework")]`, but staticlibs don't carry link
            // directives into the SwiftPM consumer — the framework has
            // to be declared explicitly here.
            linkerSettings: [
                .linkedFramework("SystemConfiguration"),
            ]
        ),
    ]
)
