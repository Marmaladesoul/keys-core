#!/usr/bin/env bash
#
# Scenario: a multi-field conflict resolves FIELD BY FIELD — the
# resolver UI's mixed outcome ("keep my username, take their notes"),
# headless. Two devices edit different values on the same two fields;
# the resolution takes local for one field and remote for the other,
# and the mixed result must survive a reopen AND converge across both
# replicas after sync-back.
#
# Teeth: an all-one-side resolver (yesterday's keyhole) cannot produce
# this outcome — both assertions would pin to the same device's values.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Shared" --username orig-user >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Shared/ {print $1; exit}')"
"$KEYHOLE" update-entry "$A" "$uuid" --notes orig-notes >/dev/null
cp "$A" "$B"

# Diverge BOTH fields on BOTH devices.
"$KEYHOLE" update-entry "$A" "$uuid" --username a-user --notes a-notes >/dev/null
"$KEYHOLE" update-entry "$B" "$uuid" --username b-user --notes b-notes >/dev/null

"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" show-conflict "$A" --entry "$uuid" | grep -q "field Notes" \
    || { echo "FAIL: expected a Notes delta alongside UserName"; exit 1; }

# Mixed resolution: keep A's username, take B's notes.
"$KEYHOLE" resolve "$A" --entry "$uuid" --choose local --field Notes=remote >/dev/null

# The mixed result, read from disk in a fresh mirror.
rm -rf "$A.mirror"
"$KEYHOLE" list "$A" | grep -q '<a-user>' \
    || { echo "FAIL: local-side username (a-user) lost in mixed resolution"; exit 1; }

# Notes aren't in list output; prove the remote notes landed via the
# digest: a vault hand-built to the expected mixed state must digest
# identically to A.
EXPECT="$TMP/expect.kdbx"
cp "$B" "$EXPECT"  # b-notes already in place...
rm -rf "$EXPECT.mirror"
"$KEYHOLE" update-entry "$EXPECT" "$uuid" --username a-user >/dev/null  # ...overlay a-user
da="$("$KEYHOLE" digest "$A")"
de="$("$KEYHOLE" digest "$EXPECT")"
[ "$da" = "$de" ] \
    || { echo "FAIL: mixed resolution does not match expected a-user+b-notes state"; exit 1; }

# And the mixed outcome converges: B adopts A's resolution.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" list-conflicts "$B" | grep -q '(no held conflicts)' \
    || { echo "FAIL: B re-parked the mixed resolution"; exit 1; }
db="$("$KEYHOLE" digest "$B")"
[ "$da" = "$db" ] \
    || { echo "FAIL: replicas did not converge on the mixed result"; exit 1; }

echo "PASS: per-field resolution produces the mixed outcome, survives reopen, and converges across replicas"
