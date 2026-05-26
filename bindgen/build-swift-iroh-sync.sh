#!/usr/bin/env bash
# Build the macOS-universal Swift bindings for `keys-iroh-sync`.
#
# Sibling to `build-swift.sh` (which builds `keys-ffi`). The two crates
# ship with deliberately different uniffi versions (keys-ffi → 0.28,
# keys-iroh-sync → 0.29), so they each need their own bindgen binary
# and their own xcframework. Their scaffolding doesn't conflict at
# link time because each crate emits its own dylib symbols.
#
# Outputs (all under repo root):
#   target/universal-apple-darwin/<profile>/libkeys_iroh_sync.a
#   swift-harness-iroh-sync/Sources/KeysIrohSyncFFI/KeysIrohSyncFFI.swift
#   swift-harness-iroh-sync/KeysIrohSyncFFI.xcframework/
#
# Pre-reqs:
#   - rust toolchain with `aarch64-apple-darwin` and `x86_64-apple-darwin` targets
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

UNIVERSAL_DIR="target/universal-apple-darwin/$PROFILE_DIR"
HEADERS_STAGING="target/swift-bindgen-iroh-sync/headers"
SWIFT_OUT="target/swift-bindgen-iroh-sync/swift"
HARNESS_SOURCES="swift-harness-iroh-sync/Sources/$SWIFT_MODULE"
XCF_OUT="swift-harness-iroh-sync/$SWIFT_MODULE.xcframework"

# 1. Per-target rust builds for the FFI staticlib.
for target in aarch64-apple-darwin x86_64-apple-darwin; do
    echo "==> cargo build $CARGO_PROFILE_FLAG --target $target -p $CRATE"
    # shellcheck disable=SC2086
    cargo build $CARGO_PROFILE_FLAG --target "$target" -p "$CRATE"
done

# 2. lipo to universal.
mkdir -p "$UNIVERSAL_DIR"
lipo -create \
    "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    "target/x86_64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    -output "$UNIVERSAL_DIR/$LIB_NAME"

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

# 5. Assemble the xcframework.
rm -rf "$XCF_OUT"
xcodebuild -create-xcframework \
    -library "$UNIVERSAL_DIR/$LIB_NAME" \
    -headers "$HEADERS_STAGING/nested" \
    -output "$XCF_OUT"

echo "==> done"
echo "    xcframework:   $XCF_OUT"
echo "    swift sources: $HARNESS_SOURCES"
