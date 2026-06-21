#!/usr/bin/env bash
#
# Scenario: "a fresh ingest rejects a wrong master password, and the
# error carries a marker a consumer can recognise as wrong-password."
#
# Two things this pins:
#   1. The slow path (no mirror → full `ingest_from_kdbx`) actually
#      REJECTS a wrong password. This is the correctness a consumer's
#      unlock fast-path falls through to: when it can't cheaply verify the
#      typed password, it does a full ingest and relies on *this*
#      rejection to catch a wrong password.
#   2. The rejection message contains a stable marker substring a consumer
#      can match to classify the failure as wrong-password rather than a
#      generic open failure. The FFI collapses kdbx-open failures into
#      `EngineError.Internal("open kdbx: …")` carrying keepass-core's
#      message verbatim, so a keepass-core reword would silently break
#      that classification. This is the canary for that drift.
#
# Keep these markers in sync with whatever substrings a consumer matches
# to classify a wrong-password unlock failure.
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

# Teeth + canary: the message must carry a marker a consumer's classifier
# recognises. If keepass-core rewords its wrong-key error, this fails
# loudly here (a cheap Rust-side red) instead of silently degrading a
# consumer's unlock UX to a generic error.
if echo "$out" | grep -qiE "wrong password|header hmac mismatch|wrong key or corrupt|decryption failed"; then
    echo "PASS: wrong-password ingest is rejected and carries a marker a consumer can classify on"
else
    echo "FAIL: wrong-password ingest was rejected, but the message lacks ANY marker a consumer's"
    echo "      wrong-password classifier would match — a consumer would show a generic error."
    echo "      Update the markers here and in any consumer classifier to the new wording."
    exit 1
fi

# Sanity: the correct password still opens it (the rejection wasn't a
# blanket "this file is broken").
rm -rf "$VAULT.mirror"
KEYHOLE_PASSWORD="$CORRECT" "$KEYHOLE" inspect "$VAULT" >/dev/null 2>&1 \
    || { echo "FAIL: correct password no longer opens the vault after a rejected attempt"; exit 1; }
