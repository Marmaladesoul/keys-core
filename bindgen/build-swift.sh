#!/usr/bin/env bash
# Build the macOS-universal Swift bindings for `keys-ffi`.
#
# Outputs (all under repo root):
#   target/universal-apple-darwin/<profile>/libkeys_ffi.a
#   swift-harness/Sources/KeysCoreFFI/KeysCoreFFI.swift
#   swift-harness/KeysCoreFFI.xcframework/
#
# Both `swift-harness/Sources/KeysCoreFFI/` and the xcframework are
# gitignored — they're regenerated artifacts. The Swift package source
# of truth is `swift-harness/Package.swift` plus the test sources.
#
# Idempotency: the script is deterministic — running it twice in a row
# produces a byte-identical tree under both regenerated paths. CI verifies.
#
# Pre-reqs:
#   - rust toolchain with `aarch64-apple-darwin` and `x86_64-apple-darwin` targets
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

UNIVERSAL_DIR="target/universal-apple-darwin/$PROFILE_DIR"
HEADERS_STAGING="target/swift-bindgen/headers"
SWIFT_OUT="target/swift-bindgen/swift"
HARNESS_SOURCES="swift-harness/Sources/$SWIFT_MODULE"
XCF_OUT="swift-harness/$SWIFT_MODULE.xcframework"

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

# 5. Assemble the xcframework. xcodebuild emits a deterministic Info.plist
#    given the same inputs, so re-running is idempotent.
rm -rf "$XCF_OUT"
xcodebuild -create-xcframework \
    -library "$UNIVERSAL_DIR/$LIB_NAME" \
    -headers "$HEADERS_STAGING" \
    -output "$XCF_OUT"

echo "==> done"
echo "    xcframework:   $XCF_OUT"
echo "    swift sources: $HARNESS_SOURCES"
