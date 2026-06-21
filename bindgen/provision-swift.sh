#!/usr/bin/env bash
# Provision a keys-core FFI crate's Swift bindings for a consuming app —
# either by downloading a *verified prebuilt* artifact from a tagged release,
# or by building locally. Drop-in replacement for calling build-swift*.sh
# directly from an app's pre-build phase.
#
#   ./provision-swift.sh [keys-ffi|keys-iroh-sync]
#
# Behaviour (env-driven):
#   KEYS_CORE_VERSION   release tag to fetch a prebuilt artifact for (e.g.
#                       v0.1.0). Unset/empty  ->  deliberate local build.
#   KEYS_CORE_LOCAL=1   build locally even if a version is pinned. This is the
#                       EXPLICIT way to opt into a local build — e.g. while
#                       iterating on keys-core, or if a release is unavailable.
#
# A local build only ever happens when explicitly asked for (no pin, or
# KEYS_CORE_LOCAL=1) — never silently. With a pin set, the prebuilt path is
# REQUIRED: download <FW>-bindings.tar.gz + checksums.txt, verify the SHA-256
# and the SLSA build-provenance attestation (if `gh` is present), then extract
# the xcframework + generated Sources. If any step fails it exits non-zero
# (loud) and tells you to rerun with KEYS_CORE_LOCAL=1 to build locally instead.
# Already provisioned for the pinned version => fast no-op (call every build).

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CRATE="${1:-keys-ffi}"
case "$CRATE" in
  keys-ffi)       FW=KeysCoreFFI;     HARNESS=swift-harness;           BUILD=bindgen/build-swift.sh ;;
  keys-iroh-sync) FW=KeysIrohSyncFFI; HARNESS=swift-harness-iroh-sync; BUILD=bindgen/build-swift-iroh-sync.sh ;;
  *) echo "provision-swift: unknown crate '$CRATE' (expected keys-ffi|keys-iroh-sync)" >&2; exit 2 ;;
esac

REPO_SLUG="Marmaladesoul/keys-core"
VERSION="${KEYS_CORE_VERSION:-}"
ASSET="$FW-bindings.tar.gz"
MARKER="$HARNESS/.provisioned-version"

build_local() { echo "provision-swift[$FW]: deliberate local build"; exec "$BUILD"; }

# --- decide: local build (only when explicitly asked), or fetch a pinned prebuilt? ---
[ "${KEYS_CORE_LOCAL:-0}" = "1" ] && build_local
[ -z "$VERSION" ] && build_local

# Fast path: already provisioned for this exact version.
if [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$VERSION" ] && [ -d "$HARNESS/$FW.xcframework" ]; then
  echo "provision-swift[$FW]: already provisioned $VERSION — skipping"
  exit 0
fi

echo "provision-swift[$FW]: fetching prebuilt $VERSION from $REPO_SLUG"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

fetch() {
  if command -v gh >/dev/null 2>&1; then
    gh release download "$VERSION" -R "$REPO_SLUG" -p "$1" -D "$TMP" --clobber
  else
    curl -fsSL "https://github.com/$REPO_SLUG/releases/download/$VERSION/$1" -o "$TMP/$1"
  fi
}

if ! fetch "$ASSET" || ! fetch "checksums.txt"; then
  echo "provision-swift[$FW]: ERROR — could not download prebuilt $VERSION from $REPO_SLUG." >&2
  echo "  Does the tag exist with its release assets? To build keys-core locally" >&2
  echo "  instead, rerun with KEYS_CORE_LOCAL=1." >&2
  exit 1
fi

# Integrity: SHA-256 must match the published checksum.
if ! ( cd "$TMP" && grep " $ASSET\$" checksums.txt | shasum -a 256 -c - ); then
  echo "provision-swift[$FW]: CHECKSUM MISMATCH for $ASSET — refusing to use it" >&2
  exit 1
fi

# Provenance: verify the SLSA attestation if gh is present (hard-fail if it
# runs and fails; warn-only if gh is unavailable, since the checksum still held).
if command -v gh >/dev/null 2>&1; then
  if gh attestation verify "$TMP/$ASSET" -R "$REPO_SLUG" >/dev/null 2>&1; then
    echo "provision-swift[$FW]: build-provenance attestation verified ✓"
  else
    echo "provision-swift[$FW]: ATTESTATION verification FAILED for $ASSET — refusing to use it" >&2
    exit 1
  fi
else
  echo "provision-swift[$FW]: gh CLI not found — provenance unverified (checksum OK)" >&2
fi

# Install: replace the generated xcframework + Sources from the artifact.
rm -rf "$HARNESS/$FW.xcframework" "$HARNESS/Sources/$FW"
tar -xzf "$TMP/$ASSET" -C "$HARNESS"
echo "$VERSION" > "$MARKER"
echo "provision-swift[$FW]: provisioned prebuilt $VERSION ✓"
