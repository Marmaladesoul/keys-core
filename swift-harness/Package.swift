// swift-tools-version:5.9
//
// Swift harness for the `keys-ffi` uniffi facade, which also carries
// `keys-iroh-sync`'s exports (one native component).
//
// `KeysCoreFFI.xcframework` and `Sources/KeysCoreFFI/` are produced by
// `../bindgen/build-swift.sh` and are gitignored — run that script before
// `swift test`. The package itself is the source of truth for the harness
// shape, the test target, and the binary-target wiring.
//
// The split between `KeysCoreFFI` (generated Swift) and `KeysCoreFFIBinary`
// (xcframework with the staticlib + C headers + module.modulemap) lets
// SwiftPM consume the binary structurally — no `unsafeFlags` needed.

import PackageDescription

let package = Package(
    name: "KeysCoreFFI",
    // `KeysCoreFFI.xcframework` ships ios-arm64 and
    // ios-arm64_x86_64-simulator slices alongside the macOS one (see
    // ../bindgen/build-swift.sh), so the manifest declares iOS too —
    // without it SwiftPM refuses to resolve the package for an iOS
    // consumer regardless of what the binary contains.
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "KeysCoreFFI", targets: ["KeysCoreFFI"]),
    ],
    targets: [
        .binaryTarget(
            name: "KeysCoreFFIBinary",
            path: "KeysCoreFFI.xcframework"
        ),
        .target(
            name: "KeysCoreFFI",
            dependencies: ["KeysCoreFFIBinary"],
            path: "Sources/KeysCoreFFI",
            // The library carries keys-iroh-sync, and iroh's transitive
            // `system_configuration` crate links the SystemConfiguration
            // framework for home-network detection. The Rust crate emits
            // `#[link(name = "SystemConfiguration", kind = "framework")]`,
            // but staticlibs don't carry link directives into the SwiftPM
            // consumer — the framework has to be declared explicitly here.
            linkerSettings: [
                .linkedFramework("SystemConfiguration"),
            ]
        ),
        .testTarget(
            name: "KeysCoreFFITests",
            dependencies: ["KeysCoreFFI"],
            path: "Tests/KeysCoreFFITests"
        ),
    ]
)
