#!/usr/bin/env bash
#
# Scenario: "a file the key doesn't open is refused as the typed
# `VaultKeyRefused`, whichever file it is and whatever its format."
#
# The sibling scenarios pin a wrong password against a KDBX4 vault file
# (`wrong-password-ingest-rejected.sh`, `sync-wrong-password-no-rekey.sh`).
# This one pins the two cases they don't reach:
#   1. KDBX3. Its wrong key fails at a different point in the decrypt (CBC
#      padding / stream-start bytes, not a header HMAC), and must reach the
#      consumer as the same variant.
#   2. A peer's copy keyed under another password, while the local vault
#      opens fine. The refusal is about the copy, not the local password: a
#      consumer can set that copy aside until its owner sends another,
#      rather than asking for the password again. The local vault is left
#      exactly as it was.
# Each has its negative control: the right key opens the same file.
#
# Self-contained apart from the vendored KDBX3 fixture (public test
# credential, not a secret).

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
HERE="$(cd "$(dirname "$0")" && pwd)"
KDBX3_FIXTURE="$HERE/fixtures/kdbx3-minimal.kdbx"
KDBX3_PW='tëst pässwörd 🔑/\'
P="keyhole-vault-key-refused-pw"
OTHER="keyhole-vault-key-refused-OTHER-pw"
WRONG="keyhole-vault-key-refused-WRONG-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

# --- 1. KDBX3 under a wrong password ---------------------------------
V3="$TMP/k3.kdbx"
cp "$KDBX3_FIXTURE" "$V3"
out="$(KEYHOLE_PASSWORD="$WRONG" "$KEYHOLE" inspect "$V3" 2>&1)" \
    && fail "a KDBX3 file opened under the WRONG password"
[[ "$out" == *"VaultKeyRefused"* ]] \
    || fail "a KDBX3 wrong password wasn't refused as VaultKeyRefused: $out"
rm -rf "$V3.mirror"
KEYHOLE_PASSWORD="$KDBX3_PW" "$KEYHOLE" inspect "$V3" >/dev/null 2>&1 \
    || fail "control: the KDBX3 fixture didn't open under its own password"

# --- 2. a peer's copy under another key ------------------------------
A="$TMP/local.kdbx"
B="$TMP/other-key.kdbx"
KEYHOLE_PASSWORD="$P" "$KEYHOLE" create "$A" >/dev/null || fail "create local vault"
KEYHOLE_PASSWORD="$P" "$KEYHOLE" create-entry "$A" "Local" --username local >/dev/null \
    || fail "seed local entry"
KEYHOLE_PASSWORD="$OTHER" "$KEYHOLE" create "$B" >/dev/null || fail "create other-key copy"
before="$(md5 -q "$A" 2>/dev/null || md5sum "$A" | cut -d' ' -f1)"

out="$(KEYHOLE_PASSWORD="$P" "$KEYHOLE" ingest-peer "$A" "$B" 2>&1)" \
    && fail "a peer copy under another key was merged"
[[ "$out" == *"VaultKeyRefused"* ]] \
    || fail "a peer copy under another key wasn't refused as VaultKeyRefused: $out"

after="$(md5 -q "$A" 2>/dev/null || md5sum "$A" | cut -d' ' -f1)"
[ "$before" = "$after" ] || fail "the refused peer copy changed the local vault file"
rm -rf "$A.mirror"
listing="$(KEYHOLE_PASSWORD="$P" "$KEYHOLE" list "$A" 2>&1)" \
    || fail "control: the local vault didn't reopen from disk under its password: $listing"
[[ "$listing" == *"Local"* ]] || fail "the local vault lost its entry: $listing"

echo "PASS: KDBX3 wrong password and a peer copy under another key are both refused as VaultKeyRefused; the local vault is untouched"
