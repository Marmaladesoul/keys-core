#!/usr/bin/env bash
#
# Scenario: both sides move the SAME entry to DIFFERENT groups — last
# writer wins by floored <LocationChanged>, deterministically, on both
# replicas (5d location LWW). Unlike a field clash, a location
# divergence does NOT park: there's a total order on the move stamp, so
# the merge picks a winner silently (matching KeePassXC / the design's
# "groups: LWW, likely no conflict UI").
#
# Teeth: A's move is strictly later (pinned a clean second apart via
# `--at` — KDBX floors to seconds), so BOTH replicas must converge on
# A's destination, including the side that didn't make the winning
# move. The clock is an input here, not a `sleep` race.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "Folder-X" >/dev/null
"$KEYHOLE" create-group "$A" "Folder-Y" >/dev/null
"$KEYHOLE" create-entry "$A" "Mover" --username m >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Mover/ {print $1; exit}')"
fx="$("$KEYHOLE" list-groups "$A" | awk '/Folder-X/ {print $1; exit}')"
fy="$("$KEYHOLE" list-groups "$A" | awk '/Folder-Y/ {print $1; exit}')"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
in_group() { "$KEYHOLE" list "$1" --group "$2" | grep "$uuid" >/dev/null; }

# B moves first (older), A moves second (newer) — pinned to distinct
# seconds via --at, no wall-clock dependence.
"$KEYHOLE" --at 1000000 move-entry "$B" "$uuid" --to "$fy" >/dev/null
"$KEYHOLE" --at 2000000 move-entry "$A" "$uuid" --to "$fx" >/dev/null

# Exchange both ways. A's later move must win on both replicas.
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

"$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
    || { echo "FAIL: a location divergence must not park"; exit 1; }
in_group "$A" "$fx" || { echo "FAIL: A did not keep its own newer move"; exit 1; }
in_group "$B" "$fx" || { echo "FAIL: B did not adopt A's newer move (LWW)"; exit 1; }
converged || { echo "FAIL: replicas diverged after the LWW move exchange"; exit 1; }

# Survives a fresh disk read on the side that adopted.
rm -rf "$B.mirror"
in_group "$B" "$fx" || { echo "FAIL: adopted move did not persist on B"; exit 1; }

echo "PASS: both-sided move resolves by LocationChanged LWW and converges on both replicas"
