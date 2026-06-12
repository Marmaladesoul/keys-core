#!/usr/bin/env bash
#
# Scenario: attachments survive the full mirror → KDBX → mirror
# round-trip. set-attachment writes through the content-addressed pool
# and persists; a fresh re-ingest from disk (mirror nuked — the honest
# read) returns byte-identical content; replacing under the same name
# re-points the link; remove drops it.
#
# Cross-PEER attachment propagation is deliberately NOT asserted here:
# classify ignores attachments today (the known 5c gap — an
# attachment-only peer change verdicts InSync). The cross-peer
# scenario lands with the 5c fix; this one pins the single-replica
# storage contract that fix builds on.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/att.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Carrier" --username c >/dev/null
uuid="$("$KEYHOLE" list "$VAULT" | awk '/Carrier/ {print $1; exit}')"

# Set + read back from a fresh disk ingest.
"$KEYHOLE" set-attachment "$VAULT" "$uuid" note.txt --text "v1-content" >/dev/null
rm -rf "$VAULT.mirror"
got="$("$KEYHOLE" cat-attachment "$VAULT" "$uuid" note.txt)"
[ "$got" = "v1-content" ] \
    || { echo "FAIL: attachment did not round-trip the KDBX (got: $got)"; exit 1; }

# Replace under the same name: the link re-points to the new blob.
"$KEYHOLE" set-attachment "$VAULT" "$uuid" note.txt --text "v2-content" >/dev/null
rm -rf "$VAULT.mirror"
got="$("$KEYHOLE" cat-attachment "$VAULT" "$uuid" note.txt)"
[ "$got" = "v2-content" ] \
    || { echo "FAIL: replacing an attachment kept the old bytes (got: $got)"; exit 1; }

# Attachment changes are content: the digest must see them.
d1="$("$KEYHOLE" digest "$VAULT")"
"$KEYHOLE" set-attachment "$VAULT" "$uuid" note.txt --text "v3-content" >/dev/null
d2="$("$KEYHOLE" digest "$VAULT")"
[ "$d1" != "$d2" ] || { echo "FAIL: attachment change invisible to the digest"; exit 1; }

echo "PASS: attachments round-trip the KDBX, replace by name, and register in the content digest"
