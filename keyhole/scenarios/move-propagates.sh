#!/usr/bin/env bash
#
# Scenario: 5d opener — a one-sided entry MOVE must propagate across
# peers. A moves an entry into a folder both replicas already share;
# B ingests A; B must see the entry in the folder (the content digest
# covers per-entry location, so convergence is the assertion).
#
# Expected red while 5d is unbuilt: a pure move leaves entry CONTENT
# identical, classify verdicts InSync (its scope is fields + icon +
# attachments — location is the deferred 5d facet), and the move never
# reaches the peer: replicas diverge in location forever.
#
# STATUS: diagnostic for the 5d slice — exclude from run-all.sh until
# location reconciliation lands, then gate it.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "Folder" >/dev/null
"$KEYHOLE" create-entry "$A" "Mover" --username m >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Mover/ {print $1; exit}')"
folder="$("$KEYHOLE" list-groups "$A" | awk '/Folder/ {print $1; exit}')"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

# One-sided move on A; B ingests.
sleep 1.1
"$KEYHOLE" move-entry "$A" "$uuid" --to "$folder" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

"$KEYHOLE" list "$B" --group "$folder" | grep "$uuid" >/dev/null \
    || { echo "FAIL: one-sided move did not propagate (entry not in Folder on B)"; exit 1; }
converged || { echo "FAIL: replicas diverged after the move exchange"; exit 1; }

# And it persists.
rm -rf "$B.mirror"
"$KEYHOLE" list "$B" --group "$folder" | grep "$uuid" >/dev/null \
    || { echo "FAIL: propagated move did not persist"; exit 1; }

echo "PASS: one-sided entry move propagates and persists"
