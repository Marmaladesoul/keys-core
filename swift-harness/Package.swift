// swift-tools-version:5.9
//
// Swift harness for the `keys-ffi` uniffi facade. Slice 1 of FFI_PHASE2.
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
    platforms: [.macOS(.v13)],
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
            path: "Sources/KeysCoreFFI"
        ),
        .testTarget(
            name: "KeysCoreFFITests",
            dependencies: ["KeysCoreFFI"],
            path: "Tests/KeysCoreFFITests"
        ),
    ]
)
