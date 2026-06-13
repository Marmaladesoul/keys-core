#!/usr/bin/env bash
#
# Scenario: 5d group metadata — a one-sided group RENAME propagates,
# and a both-sided rename resolves last-writer-wins, converging on
# both replicas. Group name is part of the convergence digest, so a
# rename that doesn't propagate diverges the replicas.
#
# Pre-slice behaviour (the red): ingest_peer only ADOPTS peer-only
# groups; a group that already exists on both sides is never
# reconciled, so a rename on one side never reaches the other —
# permanent metadata divergence.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "Shared" >/dev/null
g="$("$KEYHOLE" list-groups "$A" | awk '/Shared/ {print $1}' | head -1)"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
name_on() { "$KEYHOLE" list-groups "$1" | awk -v u="$g" '$1==u {print $2}'; }

# --- one-sided rename on A → B must adopt it ------------------------
sleep 1.1
"$KEYHOLE" rename-group "$A" "$g" "Renamed-A" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
[ "$(name_on "$B")" = "Renamed-A" ] \
    || { echo "FAIL: one-sided group rename did not propagate (got: $(name_on "$B"))"; exit 1; }
converged || { echo "FAIL: replicas diverged after one-sided rename"; exit 1; }

# --- both-sided rename → newer wins on both replicas ----------------
"$KEYHOLE" rename-group "$B" "$g" "Renamed-B-old" >/dev/null
sleep 1.1
"$KEYHOLE" rename-group "$A" "$g" "Renamed-A-new" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
[ "$(name_on "$A")" = "Renamed-A-new" ] \
    || { echo "FAIL: A lost its own newer rename (got: $(name_on "$A"))"; exit 1; }
[ "$(name_on "$B")" = "Renamed-A-new" ] \
    || { echo "FAIL: B did not adopt A's newer rename (got: $(name_on "$B"))"; exit 1; }
converged || { echo "FAIL: replicas diverged after both-sided rename"; exit 1; }

# --- and the LWW result survives a fresh disk read ------------------
rm -rf "$A.mirror" "$B.mirror"
[ "$(name_on "$A")" = "Renamed-A-new" ] && [ "$(name_on "$B")" = "Renamed-A-new" ] \
    || { echo "FAIL: renamed group did not persist"; exit 1; }
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: group rename propagates one-sided and resolves both-sided by LWW, surviving reopen"
