#!/usr/bin/env bash
#
# Scenario: 5d group structure — a peer-only GROUP (one the other
# replica has never seen) is ADOPTED on ingest, and an entry moved
# into it lands there rather than falling back to root.
#
# Pre-slice behaviour (the red): ingest_peer only ever walked the
# peer's ENTRIES; a group the peer created was invisible, so
# reconcile_entry_location no-op'd (destination absent locally) and the
# peer-only-entry insert fell back to root — the move/placement was
# silently lost and the replicas diverged on structure.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Mover" --username m >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Mover/ {print $1; exit}')"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

# A creates a brand-new group B has never seen, and moves the entry in.
sleep 1.1
"$KEYHOLE" create-group "$A" "Fresh" >/dev/null
fresh="$("$KEYHOLE" list-groups "$A" | awk '/Fresh/ {print $1; exit}')"
[ -n "$fresh" ] || { echo "FAIL(precondition): could not create group"; exit 1; }
"$KEYHOLE" move-entry "$A" "$uuid" --to "$fresh" >/dev/null

# --- THE SLICE: B adopts the peer-only group AND the placement -------
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" list-groups "$B" | grep "$fresh" >/dev/null \
    || { echo "FAIL: peer-only group not adopted on B"; exit 1; }
"$KEYHOLE" list "$B" --group "$fresh" | grep "$uuid" >/dev/null \
    || { echo "FAIL: entry not placed in the adopted group on B"; exit 1; }
converged || { echo "FAIL: replicas diverged after group adoption"; exit 1; }

# --- and the adopted structure survives a fresh disk read ------------
rm -rf "$B.mirror"
"$KEYHOLE" list "$B" --group "$fresh" | grep "$uuid" >/dev/null \
    || { echo "FAIL: adopted group/placement did not persist"; exit 1; }
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: a peer-only group is adopted and the moved entry lands in it, surviving reopen"
