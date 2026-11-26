#!/usr/bin/env bash
#
# Scenario: "a fresh ingest rejects a wrong master password, as the typed
# `VaultKeyRefused` error."
#
# Two things this pins:
#   1. The slow path (no mirror → full ingest from the file) actually
#      REJECTS a wrong password. This is the correctness a consumer's
#      unlock fast-path falls through to: when it can't cheaply verify the
#      typed password, it does a full ingest and relies on *this*
#      rejection to catch a wrong password.
#   2. The rejection is `EngineError::VaultKeyRefused`, the variant a
#      consumer branches on to say "wrong password", rather than an
#      `Internal` error carrying keepass-core's wording. A consumer never
#      matches error text, so a keepass-core reword can't break it.
#
# Self-contained: keyhole's own `create` / `inspect`, no keepassxc-cli.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
CORRECT="keyhole-correct-pw"
WRONG="keyhole-wrong-pw-DELIBERATELY-WRONG"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

KEYHOLE_PASSWORD="$CORRECT" "$KEYHOLE" create "$VAULT" >/dev/null \
    || { echo "FAIL: could not create seed vault"; exit 1; }

# Force the slow path: no mirror → Session::open ingests from disk.
rm -rf "$VAULT.mirror"

set +e
out="$(KEYHOLE_PASSWORD="$WRONG" "$KEYHOLE" inspect "$VAULT" 2>&1)"
rc=$?
set -e

echo "note: fresh ingest under the wrong password — rc=$rc, output:"
echo "$out" | sed 's/^/    /'

if [ "$rc" -eq 0 ]; then
    echo "FAIL: a fresh ingest with the WRONG password SUCCEEDED — wrong passwords are not being rejected"
    exit 1
fi

# Teeth: keyhole prints the FFI error's variant, so the typed refusal must
# be what came back (not, say, an Internal wrapping keepass-core's text).
if echo "$out" | grep -q "VaultKeyRefused"; then
    echo "PASS: wrong-password ingest is rejected as VaultKeyRefused"
else
    echo "FAIL: wrong-password ingest was rejected, but not as VaultKeyRefused — a"
    echo "      consumer branching on the variant would show a generic error."
    exit 1
fi

# Sanity: the correct password still opens it (the rejection wasn't a
# blanket "this file is broken").
rm -rf "$VAULT.mirror"
KEYHOLE_PASSWORD="$CORRECT" "$KEYHOLE" inspect "$VAULT" >/dev/null 2>&1 \
    || { echo "FAIL: correct password no longer opens the vault after a rejected attempt"; exit 1; }
