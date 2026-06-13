#!/usr/bin/env bash
# Build the macOS + iOS Swift bindings for `keys-ffi`.
#
# Outputs (all under repo root):
#   target/universal-apple-darwin/<profile>/libkeys_ffi.a       (macOS universal)
#   target/universal-apple-iossimulator/<profile>/libkeys_ffi.a (iOS sim universal)
#   target/aarch64-apple-ios/<profile>/libkeys_ffi.a            (iOS device)
#   swift-harness/Sources/KeysCoreFFI/KeysCoreFFI.swift
#   swift-harness/KeysCoreFFI.xcframework/
#
# The xcframework carries three slices — macOS universal, iOS device
# (arm64), and iOS simulator universal (arm64 + x86_64) — so both
# Keys-Mac and the future Keys-iOS target link the same artifact and
# Xcode picks the matching slice automatically.
#
# Both `swift-harness/Sources/KeysCoreFFI/` and the xcframework are
# gitignored — they're regenerated artifacts. The Swift package source
# of truth is `swift-harness/Package.swift` plus the test sources.
#
# Idempotency: the script is deterministic — running it twice in a row
# produces a byte-identical tree under both regenerated paths. CI verifies.
#
# Pre-reqs:
#   - rust toolchain with the Apple targets:
#       aarch64-apple-darwin x86_64-apple-darwin
#       aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   - `xcodebuild`, `lipo` (Xcode command line tools)
#
# The Swift bindgen is a workspace bin — `cargo run -p uniffi-bindgen-swift`
# — so its version stays locked to the `uniffi` dep in `keys-ffi/Cargo.toml`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CRATE=keys-ffi
LIB_NAME=libkeys_ffi.a
# C_MODULE: name of the C-shim module emitted by uniffi-bindgen-swift.
# The generated Swift sources do `import keys_ffiFFI` based on the crate's
# uniffi namespace (`keys_ffi`) plus an `FFI` suffix — so the modulemap
# must declare that exact name. The Swift-facing module that consumers
# `import` is `KeysCoreFFI`, defined by the SwiftPM target.
C_MODULE=keys_ffiFFI
SWIFT_MODULE=KeysCoreFFI

PROFILE="${PROFILE:-release}"
PROFILE_DIR="$PROFILE"
CARGO_PROFILE_FLAG=""
if [[ "$PROFILE" == "release" ]]; then
    CARGO_PROFILE_FLAG="--release"
fi

MACOS_UNIVERSAL_DIR="target/universal-apple-darwin/$PROFILE_DIR"
IOS_SIM_UNIVERSAL_DIR="target/universal-apple-iossimulator/$PROFILE_DIR"
IOS_DEVICE_LIB="target/aarch64-apple-ios/$PROFILE_DIR/$LIB_NAME"
HEADERS_STAGING="target/swift-bindgen/headers"
SWIFT_OUT="target/swift-bindgen/swift"
HARNESS_SOURCES="swift-harness/Sources/$SWIFT_MODULE"
XCF_OUT="swift-harness/$SWIFT_MODULE.xcframework"

# Apple targets, grouped into the three xcframework slices below. The two
# simulator targets get lipo'd into one universal-simulator staticlib; the
# two macOS targets into one universal-macOS staticlib; device arm64 stays
# standalone. Ordering is fixed so the build is deterministic.
MACOS_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
IOS_SIM_TARGETS=(aarch64-apple-ios-sim x86_64-apple-ios)
IOS_DEVICE_TARGET=aarch64-apple-ios

# 1. Per-target rust builds for the FFI staticlib.
#
# macOS builds every crate-type (unchanged — Keys-Mac has consumed this
# exact output). iOS builds *only* the staticlib: the crate's `cdylib`
# crate-type fails to link for iOS because openssl-sys — pulled in via
# rusqlite/SQLCipher → keys-engine — references the `___chkstk_darwin`
# compiler-rt builtin that rustc's standalone cdylib link step doesn't
# supply. We never ship the cdylib to iOS: the xcframework consumes only
# the `.a`, and the final iOS app link resolves the builtin. Restricting
# to `--crate-type staticlib` is therefore correct, not a workaround.
for target in "${MACOS_TARGETS[@]}"; do
    echo "==> cargo build $CARGO_PROFILE_FLAG --target $target -p $CRATE"
    # shellcheck disable=SC2086
    cargo build $CARGO_PROFILE_FLAG --target "$target" -p "$CRATE"
done
for target in "$IOS_DEVICE_TARGET" "${IOS_SIM_TARGETS[@]}"; do
    echo "==> cargo rustc $CARGO_PROFILE_FLAG --target $target -p $CRATE --crate-type staticlib"
    # shellcheck disable=SC2086
    cargo rustc $CARGO_PROFILE_FLAG --target "$target" -p "$CRATE" --crate-type staticlib
done

# 2. lipo each multi-arch group to a universal staticlib.
mkdir -p "$MACOS_UNIVERSAL_DIR" "$IOS_SIM_UNIVERSAL_DIR"
lipo -create \
    "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    "target/x86_64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    -output "$MACOS_UNIVERSAL_DIR/$LIB_NAME"
lipo -create \
    "target/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB_NAME" \
    "target/x86_64-apple-ios/$PROFILE_DIR/$LIB_NAME" \
    -output "$IOS_SIM_UNIVERSAL_DIR/$LIB_NAME"

# 3. Generate Swift bindings (sources + headers + modulemap) from the
#    aarch64 staticlib — uniffi-bindgen-swift's goblin-based parser
#    can't read fat (lipo'd) archives, and the embedded uniffi metadata
#    is identical across architectures so picking either single-arch
#    lib is correct. The universal lib is only used for linking via
#    the xcframework below.
rm -rf "$HEADERS_STAGING" "$SWIFT_OUT"
mkdir -p "$HEADERS_STAGING" "$SWIFT_OUT"

cargo run --release -p uniffi-bindgen-swift -- \
    --module-name "$C_MODULE" \
    --swift-sources \
    "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    "$SWIFT_OUT"

cargo run --release -p uniffi-bindgen-swift -- \
    --module-name "$C_MODULE" \
    --headers \
    --modulemap \
    --modulemap-filename module.modulemap \
    "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    "$HEADERS_STAGING"

# 4. Stage Swift sources for SwiftPM.
rm -rf "$HARNESS_SOURCES"
mkdir -p "$HARNESS_SOURCES"
cp "$SWIFT_OUT"/*.swift "$HARNESS_SOURCES/"

# 5. Assemble the xcframework with all three slices. The headers are
#    architecture-independent, so every slice reuses the same staging dir.
rm -rf "$XCF_OUT"
xcodebuild -create-xcframework \
    -library "$MACOS_UNIVERSAL_DIR/$LIB_NAME" \
    -headers "$HEADERS_STAGING" \
    -library "$IOS_DEVICE_LIB" \
    -headers "$HEADERS_STAGING" \
    -library "$IOS_SIM_UNIVERSAL_DIR/$LIB_NAME" \
    -headers "$HEADERS_STAGING" \
    -output "$XCF_OUT"

# 6. Canonicalise the Info.plist. With more than one slice, xcodebuild
#    orders the AvailableLibraries array non-deterministically, which would
#    break the run-twice idempotency gate; this sorts it into a fixed order.
/usr/bin/python3 "$(dirname "${BASH_SOURCE[0]}")/normalise-xcframework-plist.py" \
    "$XCF_OUT/Info.plist"

echo "==> done"
echo "    xcframework:   $XCF_OUT"
echo "    swift sources: $HARNESS_SOURCES"
