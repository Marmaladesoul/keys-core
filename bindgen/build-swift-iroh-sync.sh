#!/usr/bin/env bash
# Build the macOS + iOS Swift bindings for `keys-iroh-sync`.
#
# Sibling to `build-swift.sh` (which builds `keys-ffi`). The two crates
# ship with deliberately different uniffi versions (keys-ffi → 0.28,
# keys-iroh-sync → 0.29), so they each need their own bindgen binary
# and their own xcframework. Their scaffolding doesn't conflict at
# link time because each crate emits its own dylib symbols.
#
# Outputs (all under repo root):
#   target/universal-apple-darwin/<profile>/libkeys_iroh_sync.a       (macOS universal)
#   target/universal-apple-iossimulator/<profile>/libkeys_iroh_sync.a (iOS sim universal)
#   target/aarch64-apple-ios/<profile>/libkeys_iroh_sync.a            (iOS device)
#   swift-harness-iroh-sync/Sources/KeysIrohSyncFFI/KeysIrohSyncFFI.swift
#   swift-harness-iroh-sync/KeysIrohSyncFFI.xcframework/
#
# The xcframework carries three slices — macOS universal, iOS device
# (arm64), and iOS simulator universal (arm64 + x86_64) — so both
# Keys-Mac and the future Keys-iOS target link the same artifact.
#
# Pre-reqs:
#   - rust toolchain with the Apple targets:
#       aarch64-apple-darwin x86_64-apple-darwin
#       aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   - `xcodebuild`, `lipo` (Xcode command line tools)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CRATE=keys-iroh-sync
LIB_NAME=libkeys_iroh_sync.a
# The crate's uniffi namespace is `keys_iroh_sync` (crate name with
# hyphens → underscores). The bindgen emits the C-shim module name as
# `<namespace>FFI`.
C_MODULE=keys_iroh_syncFFI
SWIFT_MODULE=KeysIrohSyncFFI

PROFILE="${PROFILE:-release}"
PROFILE_DIR="$PROFILE"
CARGO_PROFILE_FLAG=""
if [[ "$PROFILE" == "release" ]]; then
    CARGO_PROFILE_FLAG="--release"
fi

MACOS_UNIVERSAL_DIR="target/universal-apple-darwin/$PROFILE_DIR"
IOS_SIM_UNIVERSAL_DIR="target/universal-apple-iossimulator/$PROFILE_DIR"
IOS_DEVICE_LIB="target/aarch64-apple-ios/$PROFILE_DIR/$LIB_NAME"
HEADERS_STAGING="target/swift-bindgen-iroh-sync/headers"
SWIFT_OUT="target/swift-bindgen-iroh-sync/swift"
HARNESS_SOURCES="swift-harness-iroh-sync/Sources/$SWIFT_MODULE"
XCF_OUT="swift-harness-iroh-sync/$SWIFT_MODULE.xcframework"

# Apple targets, grouped into the three xcframework slices below. The two
# simulator targets get lipo'd into one universal-simulator staticlib; the
# two macOS targets into one universal-macOS staticlib; device arm64 stays
# standalone. Ordering is fixed so the build is deterministic.
MACOS_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
IOS_SIM_TARGETS=(aarch64-apple-ios-sim x86_64-apple-ios)
IOS_DEVICE_TARGET=aarch64-apple-ios

# 1. Per-target rust builds for the FFI staticlib.
#
# macOS builds every crate-type (unchanged). iOS builds *only* the
# staticlib — the same policy as build-swift.sh. keys-iroh-sync's cdylib
# happens to link for iOS today (no openssl-sys in its tree), but the
# xcframework only ever consumes the `.a`, so building just the staticlib
# keeps the two scripts symmetric and skips an unused cdylib link.
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

# 3. Generate Swift bindings using the 0.29-pinned bindgen sibling.
rm -rf "$HEADERS_STAGING" "$SWIFT_OUT"
mkdir -p "$HEADERS_STAGING" "$SWIFT_OUT"

cargo run --release -p uniffi-bindgen-swift-029 -- \
    --module-name "$C_MODULE" \
    --swift-sources \
    "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    "$SWIFT_OUT"

cargo run --release -p uniffi-bindgen-swift-029 -- \
    --module-name "$C_MODULE" \
    --headers \
    --modulemap \
    --modulemap-filename module.modulemap \
    "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    "$HEADERS_STAGING"

# 3b. Re-nest headers under a module-named subdir so they don't collide
# with KeysCoreFFI's `Headers/module.modulemap` when both xcframeworks
# land in Xcode's `BUILT_PRODUCTS_DIR/include/`. Without this nesting
# Xcode raises "Multiple commands produce include/module.modulemap".
HEADERS_NESTED="$HEADERS_STAGING/nested/$SWIFT_MODULE"
rm -rf "$HEADERS_STAGING/nested"
mkdir -p "$HEADERS_NESTED"
mv "$HEADERS_STAGING"/*.h "$HEADERS_STAGING"/module.modulemap "$HEADERS_NESTED/"

# 4. Stage Swift sources for SwiftPM.
rm -rf "$HARNESS_SOURCES"
mkdir -p "$HARNESS_SOURCES"
cp "$SWIFT_OUT"/*.swift "$HARNESS_SOURCES/"

# 5. Assemble the xcframework with all three slices. The nested headers are
#    architecture-independent, so every slice reuses the same staging dir.
rm -rf "$XCF_OUT"
xcodebuild -create-xcframework \
    -library "$MACOS_UNIVERSAL_DIR/$LIB_NAME" \
    -headers "$HEADERS_STAGING/nested" \
    -library "$IOS_DEVICE_LIB" \
    -headers "$HEADERS_STAGING/nested" \
    -library "$IOS_SIM_UNIVERSAL_DIR/$LIB_NAME" \
    -headers "$HEADERS_STAGING/nested" \
    -output "$XCF_OUT"

# 6. Canonicalise the Info.plist so the multi-slice AvailableLibraries
#    ordering is deterministic (see build-swift.sh for the rationale).
/usr/bin/python3 "$(dirname "${BASH_SOURCE[0]}")/normalise-xcframework-plist.py" \
    "$XCF_OUT/Info.plist"

echo "==> done"
echo "    xcframework:   $XCF_OUT"
echo "    swift sources: $HARNESS_SOURCES"
