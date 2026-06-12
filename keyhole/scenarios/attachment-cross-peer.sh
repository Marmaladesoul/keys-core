#!/usr/bin/env bash
#
# Scenario: 5c — LCA-backed one-sided attachment changes propagate
# across peers. B adds an attachment → A adopts the bytes; B replaces
# it → A adopts the new bytes; A removes it → B drops it. Digest
# equality after every exchange.
#
# Scope mirrors the engine's: only LCA-backed ONE-SIDED changes
# auto-propagate. Both-sided same-name divergence stays on the
# conservative conflict path (no silent pick) until conflict rows
# learn to store attachments — the remaining 5c slice.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Carrier" --username c >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Carrier/ {print $1; exit}')"
cp "$A" "$B"

converged() { # both digests equal?
    [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]
}

# --- B adds an attachment → A adopts it ------------------------------
"$KEYHOLE" set-attachment "$B" "$uuid" doc.txt --text "from-b-v1" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
got="$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt 2>/dev/null || echo MISSING)"
[ "$got" = "from-b-v1" ] \
    || { echo "FAIL: peer attachment add did not propagate (got: $got)"; exit 1; }
converged || { echo "FAIL: replicas diverged after attachment add"; exit 1; }

# --- B replaces the bytes → A adopts the new version ------------------
"$KEYHOLE" set-attachment "$B" "$uuid" doc.txt --text "from-b-v2" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
got="$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt)"
[ "$got" = "from-b-v2" ] \
    || { echo "FAIL: peer attachment replace did not propagate (got: $got)"; exit 1; }
converged || { echo "FAIL: replicas diverged after attachment replace"; exit 1; }

# --- A removes it → B drops it ----------------------------------------
"$KEYHOLE" remove-attachment "$A" "$uuid" doc.txt >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
if "$KEYHOLE" cat-attachment "$B" "$uuid" doc.txt >/dev/null 2>&1; then
    echo "FAIL: peer attachment removal did not propagate"; exit 1
fi
converged || { echo "FAIL: replicas diverged after attachment removal"; exit 1; }

# --- and the adopted state survives a fresh disk read ------------------
rm -rf "$A.mirror" "$B.mirror"
converged || { echo "FAIL: converged attachment state did not persist to the KDBX"; exit 1; }

echo "PASS: one-sided attachment add/replace/remove propagate across peers and persist"
