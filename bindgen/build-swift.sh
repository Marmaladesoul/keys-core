#!/usr/bin/env bash
# Build the macOS + iOS Swift bindings for `keys-ffi`.
#
# Outputs (all under repo root):
#   target/universal-apple-darwin/<profile>/libkeys_ffi.a       (macOS universal)
#   target/universal-apple-iossimulator/<profile>/libkeys_ffi.a (iOS sim universal)
#   target/aarch64-apple-ios/<profile>/libkeys_ffi.a            (iOS device)
#   swift-harness/Sources/KeysCoreFFI/{keys_ffi,keys_iroh_sync}.swift
#   swift-harness/KeysCoreFFI.xcframework/
#
# The xcframework carries three slices — macOS universal, iOS device
# (arm64), and iOS simulator universal (arm64 + x86_64) — so both
# Keys-Mac and the future Keys-iOS target link the same artifact and
# Xcode picks the matching slice automatically.
#
# KEYS_SWIFT_SLICES=macos builds only the macOS slice and skips the three
# iOS cross-compiles, for Mac-only consumers that don't want to pay for
# them. Unset (or `all`) builds all three slices. A macOS-only xcframework
# can't link an iOS app, so never publish one.
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
# The library carries two crates' uniffi exports, keys-ffi's and
# keys-iroh-sync's (re-exported by keys-ffi), so library mode emits a
# Swift file and a header for each.
# C_MODULE: name of the one C-shim module holding both headers. Each
# generated Swift file does `import keys_ffiFFI`: keys-ffi's from its
# uniffi namespace plus `FFI`, keys-iroh-sync's from the
# `ffi_module_name` in its uniffi.toml. The Swift-facing module that
# consumers `import` is `KeysCoreFFI`, defined by the SwiftPM target.
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

SLICES="${KEYS_SWIFT_SLICES:-all}"
case "$SLICES" in
    all|macos) ;;
    *) echo "build-swift: KEYS_SWIFT_SLICES must be 'all' or 'macos' (got '$SLICES')" >&2; exit 2 ;;
esac

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
if [[ "$SLICES" == all ]]; then
    for target in "$IOS_DEVICE_TARGET" "${IOS_SIM_TARGETS[@]}"; do
        echo "==> cargo rustc $CARGO_PROFILE_FLAG --target $target -p $CRATE --crate-type staticlib"
        # shellcheck disable=SC2086
        cargo rustc $CARGO_PROFILE_FLAG --target "$target" -p "$CRATE" --crate-type staticlib
    done
fi

# 1b. Refuse to package test scaffolding. keys-ffi's `pairing-test-clock`
#     feature exports a clock that moves only when told to, for the headless
#     driver; a pairing sheet on it never expires a code. Its
#     `pairing-test-transport` feature exports a loopback-only node binder
#     and a way to move a node's invite clock forward. `-p keys-ffi` above
#     leaves both off, but a workspace-wide build to the same target
#     directory turns them on, so check each library that was just built
#     rather than trust how it was built. One pattern per scaffold.
TEST_SCAFFOLDING_SYMBOLS=(
    "pairingtestclock"
    "bind_local_node_for_testing"
    "pairing_test_advance_clock"
)
# A symbol every build exports, to prove the search itself still works: if
# the pairing objects are ever renamed, this fails here rather than letting
# the check above pass on a name that no longer exists.
EXPECTED_PAIRING_SYMBOL="pairingdisplaysheet"
BUILT_TARGETS=("${MACOS_TARGETS[@]}")
if [[ "$SLICES" == all ]]; then
    BUILT_TARGETS+=("$IOS_DEVICE_TARGET" "${IOS_SIM_TARGETS[@]}")
fi
for target in "${BUILT_TARGETS[@]}"; do
    lib="target/$target/$PROFILE_DIR/$LIB_NAME"
    # nm's failure must fail the build, not read as "no such symbol".
    # `--no-llvm-bc`: a Rust staticlib carries LLVM bitcode in its standard
    # library objects, from a newer LLVM than Xcode's nm can parse; without
    # the flag nm exits 1 on every such library.
    lib_symbols="$(nm -g --no-llvm-bc "$lib" 2>/dev/null)" || {
        echo "error: could not list the symbols of $lib." >&2
        exit 1
    }
    # `grep -c` exits 1 on a count of zero, hence the `|| true`.
    expected_symbols="$(grep -ci "$EXPECTED_PAIRING_SYMBOL" <<<"$lib_symbols" || true)"
    if [[ "$expected_symbols" == 0 ]]; then
        echo "error: $lib exports no '$EXPECTED_PAIRING_SYMBOL' symbol; the test-scaffolding check can't be trusted." >&2
        exit 1
    fi
    for scaffold in "${TEST_SCAFFOLDING_SYMBOLS[@]}"; do
        scaffolding_symbols="$(grep -ci "$scaffold" <<<"$lib_symbols" || true)"
        if [[ "$scaffolding_symbols" != 0 ]]; then
            echo "error: $lib exports test scaffolding ('$scaffold', $scaffolding_symbols symbols)." >&2
            echo "       It was built with a pairing-test-* feature; clients must not ship it." >&2
            exit 1
        fi
    done
done

# 2. lipo each multi-arch group to a universal staticlib.
mkdir -p "$MACOS_UNIVERSAL_DIR"
lipo -create \
    "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    "target/x86_64-apple-darwin/$PROFILE_DIR/$LIB_NAME" \
    -output "$MACOS_UNIVERSAL_DIR/$LIB_NAME"
if [[ "$SLICES" == all ]]; then
    mkdir -p "$IOS_SIM_UNIVERSAL_DIR"
    lipo -create \
        "target/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB_NAME" \
        "target/x86_64-apple-ios/$PROFILE_DIR/$LIB_NAME" \
        -output "$IOS_SIM_UNIVERSAL_DIR/$LIB_NAME"
fi

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

# 5. Assemble the xcframework with the slices built above. The headers are
#    architecture-independent, so every slice reuses the same staging dir.
XCF_SLICES=(-library "$MACOS_UNIVERSAL_DIR/$LIB_NAME" -headers "$HEADERS_STAGING")
if [[ "$SLICES" == all ]]; then
    XCF_SLICES+=(-library "$IOS_DEVICE_LIB" -headers "$HEADERS_STAGING")
    XCF_SLICES+=(-library "$IOS_SIM_UNIVERSAL_DIR/$LIB_NAME" -headers "$HEADERS_STAGING")
fi
rm -rf "$XCF_OUT"
xcodebuild -create-xcframework "${XCF_SLICES[@]}" -output "$XCF_OUT"

# 6. Canonicalise the Info.plist. With more than one slice, xcodebuild
#    orders the AvailableLibraries array non-deterministically, which would
#    break the run-twice idempotency gate; this sorts it into a fixed order.
/usr/bin/python3 "$(dirname "${BASH_SOURCE[0]}")/normalise-xcframework-plist.py" \
    "$XCF_OUT/Info.plist"

echo "==> done"
echo "    xcframework:   $XCF_OUT"
echo "    swift sources: $HARNESS_SOURCES"
